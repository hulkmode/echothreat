#!/usr/bin/env python3
#'''
# _____     _            _______ _                    _   
#|  ___|   | |          / /_   _| |                  | |
#| |__  ___| |__   ___ / /  | | | |__  _ __ ___  __ _| |_
#|  __|/ __| '_ \ / _ < <   | | | '_ \| '__/ _ \/ _` | __|
#| |__| (__| | | | (_) \ \  | | | | | | | |  __/ (_| | |_
#\____/\___|_| |_|\___/ \_\ \_/ |_| |_|_|  \___|\__,_|\__|
#
#Author: Hal Denton and AI
#Description: Echo<Threat is a modular synthetic log generation tool designed for detection engineering and simulation-based verification workflows.
#Date: 2025-05-07
#Version: 1.0  
#'''
import argparse
import sys
import os
import logging
import datetime
import time
import random
import json
import yaml
from generators.windows_log_generator import generate_log

logging.basicConfig(level=logging.INFO, format='%(levelname)s: %(message)s')

def validate_file(file_path):
    if not os.path.isfile(file_path):
        logging.error("Required file '%s' not found.", file_path)
        sys.exit(1)

def ensure_output_directory(directory):
    if not os.path.exists(directory):
        try:
            os.makedirs(directory)
        except Exception as e:
            logging.error("Failed to create output directory '%s': %s", directory, e)
            sys.exit(1)

def auto_detect_config(log_source, event_id):
    return os.path.join("configs", f"user_config_{log_source}_{event_id}.yaml")

def auto_select_template(log_source, event_id, template_format):
    return f"{log_source}_{event_id}_{template_format}.j2"

def validate_throttling_args(args):
    if (args.throttle_min is not None or args.throttle_max is not None):
        if args.throttle_min is None or args.throttle_max is None:
            logging.error("Both --throttle-min and --throttle-max must be provided together.")
            sys.exit(1)
        if args.throttle_min > args.throttle_max:
            logging.error("--throttle-min should be less than or equal to --throttle-max.")
            sys.exit(1)

def fix_backslashes(json_string):
    import re
    return re.sub(r'(?<!\\)\\(?![\\/"bfnrtu])', r'\\\\', json_string)

def route_log_output(log, args, template_name, log_source=None, event_id=None):
    timestamp_str = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    log_source = log_source or args.log_source
    event_id = event_id or args.event_id

    if args.dry_run:
        logging.info("Dry run mode: Printing log only, no output will be written")
        print(log)
        return

    if args.output == "stdout":
        logging.info("Outputting log to stdout")
        print(log)

    elif args.output == "file":
        out_dir = "output"
        ensure_output_directory(out_dir)
        out_file = os.path.join(out_dir, f"{log_source}_event_{event_id}_{timestamp_str}.log")
        try:
            with open(out_file, "a", encoding="utf-8") as f:
                f.write(log + "\n")
            logging.info("Log written to %s", out_file)
        except Exception as e:
            logging.error("Error writing log to file: %s", e)
            sys.exit(1)

    elif args.output == "filebeat":
        out_dir = "output"
        ensure_output_directory(out_dir)
        out_file = os.path.join(out_dir, f"{log_source}_event_{event_id}_{timestamp_str}.ndjson")
        try:
            fixed_log = fix_backslashes(log)
            try:
                json_obj = json.loads(fixed_log)
                ndjson_log = json.dumps(json_obj, separators=(',', ':'))
            except Exception as e:
                logging.debug("JSON minification failed (%s). Using fallback.", e)
                ndjson_log = " ".join(fixed_log.split())
            with open(out_file, "a", encoding="utf-8") as f:
                f.write(ndjson_log + "\n")
            logging.info("Log written to %s for NDJSON ingestion (Filebeat)", out_file)
        except Exception as e:
            logging.error("Error writing log for Filebeat: %s", e)
            sys.exit(1)

    else:
        logging.error("Unsupported output option: %s", args.output)
        sys.exit(1)

def process_preset_chain(preset_file, args):
    try:
        with open(preset_file, 'r') as pf:
            preset_data = yaml.safe_load(pf)
    except Exception as e:
        logging.error("Error loading preset file '%s': %s", preset_file, e)
        sys.exit(1)

    if not preset_data or "chain" not in preset_data:
        logging.error("Preset file '%s' is malformed or missing a 'chain' key.", preset_file)
        sys.exit(1)

    raw_chain = preset_data["chain"]
    chain = []

    for event in raw_chain:
        repeat_count = event.get("count", 1)
        for _ in range(repeat_count):
            chain.append(event.copy())

    logging.info("Processing preset attack chain with %d events.", len(chain))

    for idx, event in enumerate(chain):
        logging.info("Processing chain event %d of %d", idx + 1, len(chain))

        event_log_source = event.get("log_source", args.log_source)
        event_config = event.get("config_override") or auto_detect_config(event_log_source, event["event_id"])
        validate_file(event_config)

        template_format = event.get("template_format", args.template_format)
        template_name = auto_select_template(event_log_source, event["event_id"], template_format)

        template_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates")
        template_path = os.path.join(template_dir, template_name)
        validate_file(template_path)

        try:
            log = generate_log(event_config, template_name, event["event_id"])
        except Exception as e:
            logging.error("Failed to generate log for chain event %d: %s", idx + 1, e)
            continue

        route_log_output(log, args, template_name, log_source=event_log_source, event_id=event["event_id"])

        event_throttle = event.get("throttle")
        if event_throttle is not None:
            logging.info("Throttling: Sleeping for %s seconds after event %d.", event_throttle, idx + 1)
            time.sleep(event_throttle)

    logging.info("Completed processing preset attack chain.")

def main():
    parser = argparse.ArgumentParser(description="Echo<Threat - Synthetic log generator for detection engineering.")
    parser.add_argument("-ls", "--log-source", choices=["sysmon", "auditd", "security"], help="Telemetry type")
    parser.add_argument("-eid", "--event-id", type=int, help="Event ID to simulate (ignored in preset mode)")
    parser.add_argument("-c", "--config", type=str, help="Path to user configuration YAML file")
    parser.add_argument("-o", "--output", choices=["stdout", "file", "filebeat"], default="stdout", help="Output destination")
    parser.add_argument("-tf", "--template-format", type=str, default="plain", help="Template format identifier")
    parser.add_argument("-at", "--audit-type", type=str, help="(Auditd only) Type of audit log to simulate")
    parser.add_argument("-dr", "--dry-run", action="store_true", help="Simulate log generation without writing to output")
    parser.add_argument("-cnt", "--count", type=int, default=1, help="Number of logs to generate")
    parser.add_argument("-th", "--throttle", type=float, default=0, help="Fixed delay between logs (seconds)")
    parser.add_argument("-tmin", "--throttle-min", type=float, help="Minimum delay between logs (random, seconds)")
    parser.add_argument("-tmax", "--throttle-max", type=float, help="Maximum delay between logs (random, seconds)")
    parser.add_argument("-p", "--preset", type=str, help="Path to a preset chain YAML file")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose debugging output")

    args = parser.parse_args()

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    validate_throttling_args(args)

    logging.info("Echo<Threat is starting...")
    logging.info(f"Log Source: {args.log_source} | Output: {args.output}")

    if args.preset:
        validate_file(args.preset)
        process_preset_chain(args.preset, args)
        sys.exit(0)

    if not args.event_id:
        logging.error("Standard mode requires --event-id. Use --preset for preset mode.")
        sys.exit(1)

    if not args.log_source:
        logging.error("--log-source is required in standard mode.")
        sys.exit(1)

    if not args.config:
        args.config = auto_detect_config(args.log_source, args.event_id)
        logging.info("Auto-detected config file: %s", args.config)
    validate_file(args.config)

    template_name = auto_select_template(args.log_source, args.event_id, args.template_format)
    template_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "templates", template_name)
    validate_file(template_path)

    start_time = time.time()

    for i in range(args.count):
        logging.info(f"Generating event {i + 1} of {args.count}")
        try:
            log = generate_log(args.config, template_name, args.event_id)
        except Exception as e:
            logging.error("Failed to generate log: %s", e)
            sys.exit(1)

        route_log_output(log, args, template_name)

        if i < args.count - 1:
            if args.throttle and args.throttle > 0:
                logging.info("Fixed throttle: Sleeping for %s seconds.", args.throttle)
                time.sleep(args.throttle)
            elif args.throttle_min is not None and args.throttle_max is not None:
                delay = random.uniform(args.throttle_min, args.throttle_max)
                logging.info("Random throttle: Sleeping for %.2f seconds.", delay)
                time.sleep(delay)

    end_time = time.time()
    elapsed = end_time - start_time
    logging.info(f"Completed log generation! Total time: %.2f seconds.", elapsed)

if __name__ == "__main__":
    main()
