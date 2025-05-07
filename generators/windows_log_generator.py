#!/usr/bin/env python3
'''
 _____     _            _______ _                    _   
|  ___|   | |          / /_   _| |                  | |
| |__  ___| |__   ___ / /  | | | |__  _ __ ___  __ _| |_
|  __|/ __| '_ \ / _ < <   | | | '_ \| '__/ _ \/ _` | __|
| |__| (__| | | | (_) \ \  | | | | | | | |  __/ (_| | |_
\____/\___|_| |_|\___/ \_\ \_/ |_| |_|_|  \___|\__,_|\__|

Author: Hal Denton and AI
Description: Echo<Threat is a modular synthetic log generation tool designed for detection engineering and simulation-based verification workflows.
Date: 2025-05-07
Version: 1.0  

'''

import yaml
import datetime
import os
from jinja2 import Environment, FileSystemLoader, TemplateNotFound
from utils.random import rand
import random as pyrandom

def generate_log(config_path, template_name, event_id, timestamp=None):
    try:
        with open(config_path, 'r') as f:
            try:
                user_config = yaml.safe_load(f)
            except yaml.YAMLError as ye:
                raise Exception(f"Error parsing YAML configuration: {ye}")
    except FileNotFoundError:
        raise Exception(f"Configuration file '{config_path}' not found.")

    mapped_config = user_config

    if timestamp:
        mapped_config["timestamp"] = timestamp
    else:
        mapped_config["timestamp"] = datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.%fZ")

    mapped_config["event_id"] = event_id

    try:
        current_dir = os.path.dirname(os.path.abspath(__file__))
        template_dir = os.path.join(current_dir, '..', 'templates')
        env = Environment(loader=FileSystemLoader(template_dir))
        env.globals["rand"] = rand
        env.globals["random"] = pyrandom.random

        template = env.get_template(template_name)
    except TemplateNotFound:
        raise Exception(f"Template file '{template_name}' not found.")
    except Exception as e:
        raise Exception(f"Error loading template '{template_name}': {e}")

    try:
        rendered_log = template.render(**mapped_config)
    except Exception as e:
        raise Exception(f"Error rendering template: {e}")

    return rendered_log
