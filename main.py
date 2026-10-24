import queue
import signal
import threading
from concurrent.futures import ThreadPoolExecutor

import yaml

from core.alerts.alert import Alert
from core.alerts.deduplicator import Deduplicator
from core.alerts.geoip import GeoIPResolver
from core.alerts.pcap_export import PcapExporter
from core.alerts.scoring import ThreatScorer
from core.capture.engine import PacketCapture
from core.capture.parser import PacketParser
from core.capture.queue import PacketQueue
from core.capture.recorder import PacketRecorder
from core.capture.ring import PacketRing
from core.detectors.baseline import BaselineDetector
from core.detectors.arp_spoof import ArpSpoofDetector
from core.detectors.brute_force import BruteForceDetector
from core.detectors.dns_anomaly import DnsAnomalyDetector
from core.detectors.port_scan import PortScanDetector
from core.detectors.syn_flood import SynFloodDetector
from core.response.engine import ResponseEngine
from core.response.firewall import FirewallManager
from db.database import init_db
from db.queries import save_alert, update_alert_repeat
from ui.tui.app import SentinelApp


def _load_config(path: str = "config/config.yaml") -> dict:
    """Loads runtime configuration parameters."""
    with open(path) as f:
        return yaml.safe_load(f)


def _handle_alert(alert: Alert, session_factory, deduper: Deduplicator,
                  scorer: ThreatScorer, deviation_for, geo_for, pcap_for,
                  app: SentinelApp) -> None:
    """Route one alert through dedup, scoring, locating and capturing it on the way.

    A new episode is persisted and shown, a repeat only bumps the stored count –
    so a storm becomes one row, not thousands. Scoring runs after dedup, never
    before, because the repeat count is one of the score's three inputs: a repeat
    re-scores higher than the first sighting did, and that is how a live attack's
    score climbs. Location and capture happen once per episode, on the new branch:
    src_ip is part of the dedup key, so an episode cannot change country, and a
    storm must leave one pcap, not thousands. deviation_for, geo_for and pcap_for
    are plain callables, so this loop stays free of the detector, the GeoIP
    database and the packet ring alike.
    """
    decision  = deduper.process(alert)
    deviation = deviation_for(alert.src_ip, alert.timestamp)

    alert.details["deviation"] = None if deviation is None else round(deviation, 1)
    alert.score = scorer.score(alert, decision.count, deviation)

    if decision.is_new:
        alert.details["geo"]  = geo_for(alert.src_ip)
        alert.details["pcap"] = pcap_for(alert)
        row_id = save_alert(session_factory, alert)
        deduper.attach_row_id(alert, row_id)
        app.call_from_thread(app.push_alert, alert)
    else:
        update_alert_repeat(session_factory, decision.row_id, decision.count,
                            alert.score, alert.details["deviation"], alert.timestamp)
        app.call_from_thread(app.push_alert_count, alert, decision.count)


def _alert_loop(alert_queue: queue.Queue, session_factory, deduper: Deduplicator,
                scorer: ThreatScorer, deviation_for, geo_for, pcap_for, app: SentinelApp) -> None:
    """Consume the alert queue, handling each alert in isolation.

    A failure on one alert (a transient DB error, an unexpected payload) is
    reported and skipped, never allowed to kill the loop – otherwise the first
    bad alert would silence persistence and the live feed for every alert after.
    """
    while True:
        try:
            alert = alert_queue.get(timeout=1)
        except queue.Empty:
            continue
        try:
            _handle_alert(alert, session_factory, deduper, scorer, deviation_for,
                          geo_for, pcap_for, app)
        except Exception as exc:
            try:
                app.call_from_thread(app.notify, f"Alert error: {exc}", severity="error")
            except Exception:
                pass


def _stop_all(components: list) -> None:
    """Stop every component at once.

    A consumer's stop() waits up to a second for its thread to wake from the
    queue and notice; stopping eight of them one by one would add those waits up.
    """
    with ThreadPoolExecutor(max_workers=len(components)) as pool:
        list(pool.map(lambda component: component.stop(), components))


def main() -> None:
    config    = _load_config()
    interface = config["network"]["interface"]
    if interface == "auto":
        interface = None

    # Persistence – build the DB and a session factory from config
    db_cfg       = config["database"]
    SessionLocal = init_db(db_cfg["path"])

    # Dependency Injection & Pipeline Assembly
    parser      = PacketParser()
    pkt_queue   = PacketQueue()
    alert_queue = queue.Queue()
    deduper     = Deduplicator(config["alerts"]["dedup_window_seconds"])
    scorer      = ThreatScorer(**config["alerts"]["scoring"])
    geoip       = GeoIPResolver.from_path(config["alerts"]["geoip"]["database_path"])

    pcap_cfg    = config["alerts"]["pcap"]
    ring        = PacketRing(window_seconds = pcap_cfg["buffer_seconds"],
                             max_packets    = pcap_cfg["max_packets"])
    exporter    = PcapExporter(ring, output_dir=pcap_cfg["output_dir"],
                               max_files=pcap_cfg["max_files"])

    consumer    = pkt_queue.subscribe()
    capture     = PacketCapture(interface=interface, parser=parser, queue=pkt_queue, ring=ring)
    ps_cfg      = config["detectors"]["port_scan"]
    ps_detector = PortScanDetector(
        pkt_queue.subscribe(),
        alert_queue,
        threshold_ports  = ps_cfg["threshold_ports"],
        window_seconds   = ps_cfg["window_seconds"],
        cooldown_seconds = ps_cfg["cooldown_seconds"],
    )

    arp_cfg      = config["detectors"]["arp_spoof"]
    arp_detector = ArpSpoofDetector(
        pkt_queue.subscribe(),
        alert_queue,
        gratuitous_threshold      = arp_cfg["gratuitous_threshold"],
        gratuitous_window_seconds = arp_cfg["gratuitous_window_seconds"],
    )

    bf_cfg      = config["detectors"]["brute_force"]
    bf_detector = BruteForceDetector(
        pkt_queue.subscribe(),
        alert_queue,
        ssh_threshold        = bf_cfg["ssh_threshold"],
        ssh_window_seconds   = bf_cfg["ssh_window_seconds"],
        http_threshold       = bf_cfg["http_threshold"],
        http_window_seconds  = bf_cfg["http_window_seconds"],
        https_threshold      = bf_cfg["https_threshold"],
        https_window_seconds = bf_cfg["https_window_seconds"],
        cooldown_seconds     = bf_cfg.get("cooldown_seconds", 60),
    )

    dns_cfg      = config["detectors"]["dns_anomaly"]
    dns_detector = DnsAnomalyDetector(
        pkt_queue.subscribe(),
        alert_queue,
        query_threshold      = dns_cfg["query_threshold"],
        query_window_seconds = dns_cfg["query_window_seconds"],
        subdomain_max_length = dns_cfg["subdomain_max_length"],
        entropy_threshold    = dns_cfg["entropy_threshold"],
        cooldown_seconds     = dns_cfg["cooldown_seconds"],
    )

    syn_cfg      = config["detectors"]["syn_flood"]
    syn_detector = SynFloodDetector(
        pkt_queue.subscribe(),
        alert_queue,
        ratio_medium     = syn_cfg["ratio_medium"],
        ratio_high       = syn_cfg["ratio_high"],
        window_seconds   = syn_cfg["window_seconds"],
        min_syn          = syn_cfg["min_syn"],
        cooldown_seconds = syn_cfg["cooldown_seconds"],
    )

    base_cfg      = config["detectors"]["baseline"]
    base_detector = BaselineDetector(
        pkt_queue.subscribe(),
        alert_queue,
        interval_seconds          = base_cfg["interval_seconds"],
        min_samples               = base_cfg["min_samples"],
        z_medium                  = base_cfg["z_medium"],
        z_high                    = base_cfg["z_high"],
        idle_evict_seconds        = base_cfg["idle_evict_seconds"],
        deviation_max_age_seconds = base_cfg["deviation_max_age_seconds"],
        session_factory           = SessionLocal,
    )

    recorder = PacketRecorder(
        pkt_queue.subscribe(),
        SessionLocal,
        batch_size      = db_cfg["packet_batch_size"],
        flush_seconds   = db_cfg["packet_flush_seconds"],
        retention_hours = db_cfg["packet_retention_hours"],
        cleanup_seconds = db_cfg["packet_cleanup_seconds"],
    )

    resp_cfg        = config["response"]
    firewall        = FirewallManager(direction=resp_cfg["direction"])
    response_engine = ResponseEngine(firewall, SessionLocal, whitelist=resp_cfg["whitelist"])

    ui_cfg = config["ui"]
    app = SentinelApp(
        packet_queue=consumer,
        session_factory=SessionLocal,
        response_engine=response_engine,
        score_high   = ui_cfg["score_high"],
        score_medium = ui_cfg["score_medium"],
    )

    pipeline = [capture, ps_detector, arp_detector, bf_detector,
                dns_detector, syn_detector, base_detector, recorder]

    # Ctrl+C only asks the UI to close; the pipeline stops below, on the one path
    # every exit takes.
    signal.signal(signal.SIGINT, lambda sig, frame: app.exit())

    for component in pipeline:
        component.start()

    threading.Thread(
        target=_alert_loop,
        args=(alert_queue, SessionLocal, deduper, scorer, base_detector.deviation_for,
              geoip.lookup, exporter.export, app),
        daemon=True,
    ).start()

    try:
        app.run()
    finally:
        # q, Ctrl+C or a crash in the UI - every way out stops the pipeline, so the
        # baseline and the packet log write what they hold before the process ends.
        _stop_all(pipeline)


if __name__ == "__main__":
    main()