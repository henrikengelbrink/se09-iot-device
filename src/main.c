/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mgos.h"
#include "mgos_wifi.h"
#include "mgos_http_server.h"
#include "mgos_rpc.h"

static void timer_cb(void *arg) {
  static bool s_tick_tock = false;
  LOG(LL_INFO,
      ("%s uptime: %.2lf, RAM: %lu, %lu free HENRIK", (s_tick_tock ? "Tick" : "Tock"),
       mgos_uptime(), (unsigned long) mgos_get_heap_size(),
       (unsigned long) mgos_get_free_heap_size()));
  s_tick_tock = !s_tick_tock;
  (void) arg;
}

static void get_random_string(char *str, size_t size)
{
    size_t i = 0;
    const char charset[] = "abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
    if (size) {
        while (i < size) {
            int key = rand() % (int) (sizeof charset - 1);
            str[i] = charset[key];
            i++;
        }
        str[size] = '\0';
    }
}

static void connect_to_wifi(char ssid[], char password[]) {
  LOG(LL_INFO, ("Wifi ssid: %s", ssid));
  LOG(LL_INFO, ("Wifi password: %s", password));

  struct mgos_config_wifi_ap ap_config = {
    .enable = false
  };
  bool apDisableSuccess = mgos_wifi_setup_ap(&ap_config);
  LOG(LL_INFO, ("Disable AP Success: %d", apDisableSuccess));

  struct mgos_config_wifi_sta sta_config = {
    .enable = true,
    .ssid = ssid,
    .pass = password,
  };
  bool staConnectSuccess = mgos_wifi_setup_sta(&sta_config);
  LOG(LL_INFO, ("Connect STA Success: %d", staConnectSuccess));
}

static void rpc_setup_wifi(struct mg_rpc_request_info * ri, void * cb_arg,
                         struct mg_rpc_frame_info * fi, struct mg_str args) {
  char *ssid = NULL;
  char *password = NULL;

  json_scanf(args.p, args.len, "{ ssid:%Q, password:%Q }", &ssid, &password);
  if (ssid == NULL || password == NULL) {
    mg_rpc_send_errorf(ri, 400, "Invalid or missing parameter");
    return;
  }
  mg_rpc_send_responsef(ri, "OK");

  connect_to_wifi(ssid, password);

  (void) cb_arg;
  (void) fi;
}

static void setup_wifi_ap() {
  static char wifiPassword[8];
  get_random_string(wifiPassword, 8);
  LOG(LL_INFO, ("### wifiPassword: %s", wifiPassword));

  struct mgos_config_wifi_ap ap_config = {
    .enable = true,
    .ssid = "esp32eh",
    .pass = wifiPassword,
    .ip = "192.168.99.1",
    .netmask = "255.255.255.0",
    .dhcp_start = "192.168.99.20",
    .dhcp_end = "192.168.99.100",
    .channel = 5,
    .max_connections = 3,
    .protocol = "BGN"
  };
  bool wifiSuccess = mgos_wifi_setup_ap(&ap_config);
  LOG(LL_INFO, ("Wifi Success: %d", wifiSuccess));
}

enum mgos_app_init_result mgos_app_init(void) {
  mgos_set_timer(5000, MGOS_TIMER_REPEAT, timer_cb, NULL);

  struct mgos_config_wifi_sta sta_cfg;
  memcpy(&sta_cfg, mgos_sys_config_get_wifi_sta(), sizeof(sta_cfg));
  LOG(LL_INFO, ("STA status %d", sta_cfg.enable));
  if (sta_cfg.enable == 0) {
    LOG(LL_INFO, ("Setup AP %d", 1));
    setup_wifi_ap();
  } else {
    LOG(LL_INFO, ("Connect STA %d", 1));
  }

  struct mg_rpc *rpc = mgos_rpc_get_global();
  mg_rpc_add_handler(rpc, "Cmd.Wifi", "{ssid: %c, password: %c}", rpc_setup_wifi, NULL);

  return MGOS_APP_INIT_SUCCESS;
}

//http://192.168.99.1/rpc/Config.Set
//{"config": {"wifi": {"sta": {"enable": true, "ssid": "iPhoneEH", "pass": "heycar123"}, "ap": {"enable": false}}}}

//http://192.168.99.1/rpc/Config.Save
//{"reboot": true}