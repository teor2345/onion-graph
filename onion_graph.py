# onion-graph: A Tor network relay connectivity scanner
# Copyright Tim Wilson-Brown (teor) 2016 - gmail: teor2345
#
# This program is free software: you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation, either version 3 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License
#   along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# Based on custom_path_selection.py from stem master >1.4.1 (git 373d56f8)
# (stem is LGPL 3)

import math
# use cryptographically secure random numbers, because why not?
import random
random = random.SystemRandom()

import time
import sys

import stem.control

# Tor control port
CONTROL_ADDR = "127.0.0.1"
# Tor Relay: 9050
# Tor Browser: 9151
# Check both: "default"
CONTROL_PORT = int(sys.argv[1]) if len(sys.argv) >= 2 else "default"

# Batch size
# This script processes about 1500-2000 paths per hour
N_GUARD = 5
N_MIDDLE = 10

# Data Resolution
# Rounding to the nearest hour allows us to work out the relay details tor was
# using to make connections. There are 3 consensuses valid at any one time:
# - Clients have the 1st consensus the hour they bootstrap from authorities.
# - Clients have the 2nd or 3rd consensus when they bootstrap from
#   fallback directory mirrors (0.2.8), or when they have been running for at
#   least an hour. 
# But it doesn't allow an adversary to determine relay connection latency at a
# high reslution (which could yield connection latency or utilisation, or
# perhaps relay load).
# Post-Processing:
# The order of log entries still allows an approximate time to be derived.
# Log entries should be sorted lexicographically to avoid this issue.
# (For similar reasons, we don't log connection_id.)
# Future relay selection schemes should randomise relays, or sort them by
# consensus weight. Processing relays in lexicographical order should be
# avoided.
LOG_RESOLUTION = 3600
# To Be Determined:
# Should we also add random noise?
# I think hourly resolution is enough, and the lexicographical ordering
# introduces randomness from relay selection into the time series. But we
# could do it just to be thorough. A consensus either way shouldn't matter
# much. Adding a random value will introduce values outside the test period.
# (They will be obvious outliers, I'm not sure if we can fix this.)
LOG_NOISE = 3600

# Rounding this value avoids revealing precise round-trip times, while still
# allowing us to determine the latency between relays.
# Post-Processing:
# Extreme values still provide significant amounts of information. Bin extreme
# values with the minimal and maximal values that comprise at least N% of the
# log entries.
# To Be Determined:
# Should this value be higher? 0.5 seconds?
ELAPSED_RESOLUTION = 0.1
# We should definitely add random noise. But given the small number of trials,
# we don't want the noise totally destroying the signal. There is already some
# noise introduced between client and relay, but statistical analysis could
# reduce or remove this.
# Post-Processing:
# Add additional random noise?
# To Be Determined:
# Should this value be higher? 0.5 seconds?
ELAPSED_NOISE = 0.1

# Placeholders for missing values
RELAY_NULL = "path_had_no_relay_here"
PATH_LENGTH_NULL = 0
TIME_NULL = 0.0
CIRCUIT_NULL = "circuit_not_built"
CIRCUIT_INVALID = "no_circuit_id"

# Success / Error Conditions
CONN_OK = "ok"
CONN_SKIP = "skip"
CONN_ERR = "error"
CONN_SKIP_SAME_RELAY = "Invalid path: same relay as guard and middle"

def add_noise_and_round(value, resolution, noise):
  """
  Add a random value between -noise and +noise to value, then round to
  resolution.
  """
  # To Be Determined:
  # Should we use a particular random distribution?
  random_noise = random.random() * noise
  return math.floor((value + random_noise) / resolution) * resolution

def blur_log_time(t):
  """
  Add random noise and round t using add_noise_and_round() with the log time
  constants.
  """
  return add_noise_and_round(t, LOG_RESOLUTION, LOG_NOISE)

def blur_elapsed_time(t):
  """
  Add random noise and round t using add_noise_and_round() with the elapsed
  time constants.
  """
  return add_noise_and_round(t, ELAPSED_RESOLUTION, ELAPSED_NOISE)

def scan(controller, path):
  """
  Build a circuit through the given path of relays, and return the time it
  took and the circuit_id built.
  """

  try:
    circuit_id = CIRCUIT_INVALID
    start_time = time.time()
    # purpose = "controller" means these circuits won't be used for anything
    circuit_id = controller.new_circuit(path, purpose = "controller",
                                        await_build = True)
    return (time.time() - start_time, circuit_id)
  finally:
    if circuit_id != CIRCUIT_INVALID:
      controller.close_circuit(circuit_id)

def report(guard, middle, path_length, time_taken, circuit_id, status,
           reason = ""):
  """
  Report current time in epoch format, guard, middle, path_length, and
  time_taken when building a circuit. If the circuit was not built,
  optionally include a free-text reason for the failure.
  Don't log the circuit_id, it provides an ordering that can be used to
  derive approximate time values.
  """
  print('%0.0f %s %s %d %0.1f %s %s' % (blur_log_time(time.time()),
                                        guard, middle, path_length,
                                        blur_elapsed_time(time_taken),
                                        status, reason))

with stem.control.Controller.from_port(address = CONTROL_ADDR,
                                       port = CONTROL_PORT) as controller:
  controller.authenticate()

  # Using Stable means that results are less likely to be affected by relay
  # downtime, but if we have multiple runs, we should exclude it
  relay_fingerprints = [desc.fingerprint
                        for desc
                        in controller.get_network_statuses()
                        if "Fast" in desc.flags]
  # check invalid then analyse behaviour separately
  # and "Valid" in desc.flags
  # and "Stable" in desc.flags

  for guard in random.sample(relay_fingerprints, N_GUARD):
    # make an initial non-logged connection to guard so that the first time
    # isn't inflated by SSL connection setup
    try:
      (time_taken, circuit_id) = scan(controller, [guard])
      report(guard, RELAY_NULL, 1, time_taken, circuit_id, CONN_OK)
      for middle in random.sample(relay_fingerprints, N_MIDDLE):
        if guard == middle:
          # don't even report this, it's an implementation detail
          #report(guard, middle, PATH_LENGTH_NULL, TIME_NULL, CIRCUIT_NULL,
          #       CONN_SKIP, CONN_SKIP_SAME_RELAY)
          continue
        try:
          (time_taken, circuit_id) = scan(controller, [guard, middle])
          report(guard, middle, 2, time_taken, circuit_id, CONN_OK)
        except Exception as exc:
          report(guard, middle, PATH_LENGTH_NULL, TIME_NULL, CIRCUIT_NULL,
                 CONN_ERR, exc)
    except Exception as exc:
      report(guard, RELAY_NULL, PATH_LENGTH_NULL, TIME_NULL, CIRCUIT_NULL,
             CONN_ERR, exc)
