//ENABLE PPP AND PAP IN menuconfig
#include "freertos/FreeRTOS.h"
#include "freertos/event_groups.h"
#include "freertos/task.h"
#include "esp_system.h"
#include "esp_wifi.h"
#include "esp_log.h"
#include "esp_event.h"
#include "nvs_flash.h"
#include "freertos/semphr.h"

#include <stdio.h>
#include <string.h>
#include "aws_iot_config.h"
#include "aws_iot_log.h"
#include "aws_iot_version.h"
#include "aws_iot_mqtt_client_interface.h"
#include "bmp280.h"
#include "esp_idf_lib_helpers.h"
#include "i2cdev.h"

#include "driver/uart.h"

#include "netif/ppp/pppos.h"
#include "netif/ppp/ppp.h"
#include "lwip/err.h"
#include "lwip/sockets.h"
#include "lwip/sys.h"
#include "lwip/netdb.h"
#include "lwip/dns.h"
#include "netif/ppp/pppapi.h"

#include "mbedtls/platform.h"
#include "mbedtls/net.h"
#include "mbedtls/esp_debug.h"
#include "mbedtls/ssl.h"
#include "mbedtls/entropy.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/error.h"
#include "mbedtls/certs.h"

#include <esp_event.h>
#include <esp_wifi.h>

#include "lwip/apps/sntp.h"
#include "cJSON.h"

#include "libGSM.h"

#ifdef CONFIG_GSM_USE_WIFI_AP
#include "lwip/api.h"
#include "lwip/err.h"
#include "lwip/netdb.h"
#endif

#define EXAMPLE_TASK_PAUSE	300		// pause between task runs in seconds
#define TASK_SEMAPHORE_WAIT 140000	// time to wait for mutex in miliseconds

QueueHandle_t http_mutex;

static const char *TIME_TAG = "[SNTP]";
static const char *TAG = "MAIN";

unsigned char mac[6] = {0};


#ifdef CONFIG_GSM_SEND_SMS
static const char *SMS_TAG = "[SMS]";
#endif

#ifdef CONFIG_GSM_USE_WIFI_AP
static const char *WEBSRV_TAG = "[WebServer]";
const static char http_html_hdr[] = "HTTP/1.1 200 OK\nContent-type: text/html\n\n";
const static char http_index_html[] = "<!DOCTYPE html>"
                                     "<html>\n"
                                     "<head>\n"
                                     "  <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n"
                                     "  <style type=\"text/css\">\n"
                                     "    html, body, iframe { margin: 0; padding: 0; height: 100%; }\n"
                                     "    iframe { display: block; width: 100%; border: none; }\n"
                                     "  </style>\n"
                                     "<title>HELLO ESP32</title>\n"
                                     "</head>\n"
                                     "<body>\n"
                                     "<h1>Hello World, from ESP32!</h1>\n";
#endif

/* Set the SSID and Password via project configuration, or can set directly here */
#define DEFAULT_SSID CONFIG_EXAMPLE_WIFI_SSID
#define DEFAULT_PWD CONFIG_EXAMPLE_WIFI_PASSWORD

#if CONFIG_EXAMPLE_WIFI_ALL_CHANNEL_SCAN
#define DEFAULT_SCAN_METHOD WIFI_ALL_CHANNEL_SCAN
#elif CONFIG_EXAMPLE_WIFI_FAST_SCAN
#define DEFAULT_SCAN_METHOD WIFI_FAST_SCAN
#else
#define DEFAULT_SCAN_METHOD WIFI_FAST_SCAN
#endif /*CONFIG_EXAMPLE_SCAN_METHOD*/

#if CONFIG_EXAMPLE_WIFI_CONNECT_AP_BY_SIGNAL
#define DEFAULT_SORT_METHOD WIFI_CONNECT_AP_BY_SIGNAL
#elif CONFIG_EXAMPLE_WIFI_CONNECT_AP_BY_SECURITY
#define DEFAULT_SORT_METHOD WIFI_CONNECT_AP_BY_SECURITY
#else
#define DEFAULT_SORT_METHOD WIFI_CONNECT_AP_BY_SIGNAL
#endif /*CONFIG_EXAMPLE_SORT_METHOD*/

#if CONFIG_EXAMPLE_FAST_SCAN_THRESHOLD
#define DEFAULT_RSSI CONFIG_EXAMPLE_FAST_SCAN_MINIMUM_SIGNAL
#if CONFIG_EXAMPLE_FAST_SCAN_WEAKEST_AUTHMODE_OPEN
#define DEFAULT_AUTHMODE WIFI_AUTH_OPEN
#elif CONFIG_EXAMPLE_FAST_SCAN_WEAKEST_AUTHMODE_WEP
#define DEFAULT_AUTHMODE WIFI_AUTH_WEP
#elif CONFIG_EXAMPLE_FAST_SCAN_WEAKEST_AUTHMODE_WPA
#define DEFAULT_AUTHMODE WIFI_AUTH_WPA_PSK
#elif CONFIG_EXAMPLE_FAST_SCAN_WEAKEST_AUTHMODE_WPA2
#define DEFAULT_AUTHMODE WIFI_AUTH_WPA2_PSK
#else
#define DEFAULT_AUTHMODE WIFI_AUTH_OPEN
#endif
#else
#define DEFAULT_RSSI -127
#define DEFAULT_AUTHMODE WIFI_AUTH_OPEN
#endif /*CONFIG_EXAMPLE_FAST_SCAN_THRESHOLD*/

#define SDA_GPIO 21
#define SCL_GPIO 22
#define LED_PIN  12
#ifndef APP_CPU_NUM
#define APP_CPU_NUM PRO_CPU_NUM
#endif



/**
 * @brief Default MQTT HOST URL is pulled from the aws_iot_config.h
 */
char HostAddress[255] = AWS_IOT_MQTT_HOST;

/**
 * @brief Default MQTT port is pulled from the aws_iot_config.h
 */
uint32_t port = AWS_IOT_MQTT_PORT;


static void event_handler(void* arg, esp_event_base_t event_base,
                                int32_t event_id, void* event_data)
{
    if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_START) {
        esp_wifi_connect();
    } else if (event_base == WIFI_EVENT && event_id == WIFI_EVENT_STA_DISCONNECTED) {
        esp_wifi_connect();
    } else if (event_base == IP_EVENT && event_id == IP_EVENT_STA_GOT_IP) {
        ip_event_got_ip_t* event = (ip_event_got_ip_t*) event_data;
        ESP_LOGI(TAG, "got ip:" IPSTR, IP2STR(&event->ip_info.ip));
    }
}

void iot_subscribe_callback_handler(AWS_IoT_Client *pClient, char *topicName, uint16_t topicNameLen,
                                    IoT_Publish_Message_Params *params, void *pData) 
{
    ESP_LOGI(TAG, "Subscribe callback");
    ESP_LOGI(TAG, "%.*s\t%.*s", topicNameLen, topicName, (int) params->payloadLen, (char *)params->payload);
}

void disconnectCallbackHandler(AWS_IoT_Client *pClient, void *data) {
    ESP_LOGW(TAG, "MQTT Disconnect");
    IoT_Error_t rc = FAILURE;

    if(NULL == pClient) {
        return;
    }

    if(aws_iot_is_autoreconnect_enabled(pClient)) {
        ESP_LOGI(TAG, "Auto Reconnect is enabled, Reconnecting attempt will start now");
    } else {
        ESP_LOGW(TAG, "Auto Reconnect not enabled. Starting manual reconnect...");
        rc = aws_iot_mqtt_attempt_reconnect(pClient);
        if(NETWORK_RECONNECTED == rc) {
            ESP_LOGW(TAG, "Manual Reconnect Successful");
        } else {
            ESP_LOGW(TAG, "Manual Reconnect Failed - %d", rc);
        }
    }
}

void aws_iot_task(void *param) {
    char cPayload[200];

    int32_t i = 0;

    IoT_Error_t rc = FAILURE;

    AWS_IoT_Client client;
    IoT_Client_Init_Params mqttInitParams = iotClientInitParamsDefault;
    IoT_Client_Connect_Params connectParams = iotClientConnectParamsDefault;

    IoT_Publish_Message_Params paramsQOS0;
    IoT_Publish_Message_Params paramsQOS1;

    ESP_LOGI(TAG, "AWS IoT SDK Version %d.%d.%d-%s", VERSION_MAJOR, VERSION_MINOR, VERSION_PATCH, VERSION_TAG);

    mqttInitParams.enableAutoReconnect = false; // We enable this later below
    mqttInitParams.pHostURL = HostAddress;
    mqttInitParams.port = port;


    extern const uint8_t aws_root_ca_pem_start[] asm("_binary_root_ca_pem_start");
    extern const uint8_t aws_root_ca_pem_end[] asm("_binary_root_ca_pem_end");
    extern const uint8_t certificate_pem_crt_start[] asm("_binary_certificate_pem_crt_start");
    extern const uint8_t certificate_pem_crt_end[] asm("_binary_certificate_pem_crt_end");
    extern const uint8_t private_pem_key_start[] asm("_binary_private_pem_key_start");
    extern const uint8_t private_pem_key_end[] asm("_binary_private_pem_key_end");

    mqttInitParams.pRootCALocation = (const char *)aws_root_ca_pem_start;
    mqttInitParams.pDeviceCertLocation = (const char *)certificate_pem_crt_start;
    mqttInitParams.pDevicePrivateKeyLocation = (const char *)private_pem_key_start;
    ESP_LOGI(TAG, "Certs are embedded");

    rc = aws_iot_mqtt_init(&client, &mqttInitParams);
    if(SUCCESS != rc) {
        ESP_LOGE(TAG, "aws_iot_mqtt_init returned error : %d ", rc);
        abort();
    }

    /* Wait for WiFI to show as connected */
    //xEventGroupWaitBits(wifi_event_group, CONNECTED_BIT,
    //                   false, true, portMAX_DELAY);

    //connectParams.keepAliveIntervalInSec = 10;
    //connectParams.isCleanSession = true;
    //connectParams.MQTTVersion = MQTT_3_1_1;
    /* Client ID is set in the menuconfig of the example */
    connectParams.pClientID = CONFIG_AWS_IOT_CLIENT_ID;
    connectParams.clientIDLen = (uint16_t) strlen(CONFIG_AWS_IOT_CLIENT_ID);
    connectParams.isWillMsgPresent = false;

    ESP_LOGI(TAG, "Connecting to AWS...");
    do {
        rc = aws_iot_mqtt_connect(&client, &connectParams);
        if(SUCCESS != rc) {
            ESP_LOGE(TAG, "Error(%d) connecting to %s:%d", rc, mqttInitParams.pHostURL, mqttInitParams.port);
            vTaskDelay(1000 / portTICK_RATE_MS);
        }
    } while(SUCCESS != rc);

    /*
     * Enable Auto Reconnect functionality. Minimum and Maximum time of Exponential backoff are set in aws_iot_config.h
     *  #AWS_IOT_MQTT_MIN_RECONNECT_WAIT_INTERVAL
     *  #AWS_IOT_MQTT_MAX_RECONNECT_WAIT_INTERVAL
     */
    rc = aws_iot_mqtt_autoreconnect_set_status(&client, true);
    if(SUCCESS != rc) {
        ESP_LOGE(TAG, "Unable to set Auto Reconnect to true - %d", rc);
        abort();
    }

    const char *TOPIC = "mqttpub";
    const int TOPIC_LEN = strlen(TOPIC);

    ESP_LOGI(TAG, "Subscribing...");
    rc = aws_iot_mqtt_subscribe(&client, TOPIC, TOPIC_LEN, QOS0, iot_subscribe_callback_handler, NULL);
    if(SUCCESS != rc) {
        ESP_LOGE(TAG, "Error subscribing : %d ", rc);
        abort();
    }

    sprintf(cPayload, "%s : %d ", "hello from SDK", i);

    paramsQOS0.qos = QOS0;
    paramsQOS0.payload = (void *) cPayload;
    paramsQOS0.isRetained = 0;

    paramsQOS1.qos = QOS1;
    paramsQOS1.payload = (void *) cPayload;
    paramsQOS1.isRetained = 0;

    //bmp280_params_t params;
    //bmp280_init_default_params(&params);
    //bmp280_t dev;
    //memset(&dev, 0, sizeof(bmp280_t));

    //ESP_ERROR_CHECK(bmp280_init_desc(&dev, BMP280_I2C_ADDRESS_0, 0, SDA_GPIO, SCL_GPIO));
    //ESP_ERROR_CHECK(bmp280_init(&dev, &params));

    //bool bme280p = dev.id == BME280_CHIP_ID;
    //printf("BMP280: found %s\n", bme280p ? "BME280" : "BMP280");

    //float pressure, temperature, humidity;

    while((NETWORK_ATTEMPTING_RECONNECT == rc || NETWORK_RECONNECTED == rc || SUCCESS == rc)) {

        //Max time the yield function will wait for read messages
        rc = aws_iot_mqtt_yield(&client, 100);
        if(NETWORK_ATTEMPTING_RECONNECT == rc) {
            // If the client is attempting to reconnect we will skip the rest of the loop.
            continue;
        }

        ESP_LOGI(TAG, "Stack remaining for task '%s' is %d bytes", pcTaskGetTaskName(NULL), uxTaskGetStackHighWaterMark(NULL));
        //if (bmp280_read_float(&dev, &temperature, &pressure, &humidity) != ESP_OK)
       // {
        //    printf("Temperature/pressure reading failed\n");
       //     continue;
       // }
        //sprintf(cPayload, "Pressure: %.2f Pa, Temperature: %.2f C , Humidity: %.2f\n", pressure, temperature, humidity);
        sprintf(cPayload, "{\"MAC\" : \"%02X:%02X:%02X:%02X:%02X:%02X\", \"Pressure\" : \"1000 Pa\", \"Temperature\" : \"30 C\", \"Humidity\" : \"50 percent\", \"Latitude\" : \"%s\", \"Longitude\" : \"%s\", \"Altitude\" : \"%s\"}",mac[0],mac[1],mac[2],mac[3],mac[4],mac[5], lat, lon, alt);
        printf("\n%s\n",cPayload);
        paramsQOS0.payloadLen = strlen(cPayload);
        rc = aws_iot_mqtt_publish(&client, TOPIC, TOPIC_LEN, &paramsQOS0);

        //sprintf(cPayload, "%s : %d ", "hello from ESP32 (QOS1)", i++);
        //paramsQOS1.payloadLen = strlen(cPayload);
        //rc = aws_iot_mqtt_publish(&client, TOPIC, TOPIC_LEN, &paramsQOS1);
        
        get_GPS(); // ADD ERROR CHECK LATER AND THREADING
        vTaskDelay(300000 / portTICK_RATE_MS);
        if (rc == MQTT_REQUEST_TIMEOUT_ERROR) {
            ESP_LOGW(TAG, "QOS0 publish ack not received.");
            rc = SUCCESS;
        }
    }

    ESP_LOGE(TAG, "An error occurred in the main loop.");
    abort();
}


void app_main(void)
{
    // Turning on LED
    gpio_reset_pin(LED_PIN);
    gpio_set_direction(LED_PIN, GPIO_MODE_OUTPUT);
    gpio_set_level(LED_PIN, 1);

    //turning on modem
    gpio_set_direction(GPIO_NUM_4, GPIO_MODE_OUTPUT);
    gpio_set_level(GPIO_NUM_4, 0);
    vTaskDelay(1000/ portTICK_PERIOD_MS);                  // PUT THIS IN ITS OWN METHOD THEN CALL FROM MAIN
    gpio_set_level(GPIO_NUM_4, 1);

    esp_efuse_mac_get_default(mac);


    if (ppposInit() == 0) // initializes the UART to talk to the sim7000
    {
		ESP_LOGE("PPPoS EXAMPLE", "ERROR: GSM not initialized, HALTED");
		while (1) {
			vTaskDelay(1000 / portTICK_RATE_MS);
		}
	}


    vTaskDelay(3000 / portTICK_RATE_MS);

    	// ==== Get time from NTP server =====

	time_t now = 0;
	struct tm timeinfo = { 0 };
	int retry = 0;
	const int retry_count = 25;
     
    ip_addr_t dnsserver;
    ESP_LOGI(TIME_TAG, "SYSTEM_EVENT_STA_GOT_IP");
    inet_pton(AF_INET, "8.8.8.8", &dnsserver);
    dns_setserver(0, &dnsserver);
    inet_pton(AF_INET, "8.8.4.4", &dnsserver);
    dns_setserver(1, &dnsserver);

	time(&now);
	localtime_r(&now, &timeinfo);

	while (1) {
		printf("\r\n");
		ESP_LOGI(TIME_TAG,"OBTAINING TIME");
	    ESP_LOGI(TIME_TAG, "Initializing SNTP");
	    sntp_setoperatingmode(SNTP_OPMODE_POLL);
        sntp_setservername(0, "time.google.com");
	    //sntp_setservername(0, "pool.ntp.org");
	    sntp_init();
		ESP_LOGI(TIME_TAG,"SNTP INITIALIZED");

		// wait for time to be set
		now = 0;
		while ((timeinfo.tm_year < (2020 - 1900)) && (++retry < retry_count)) {
			ESP_LOGI(TIME_TAG, "Waiting for system time to be set... (%d/%d) (%d)", retry, retry_count, timeinfo.tm_year);
			vTaskDelay(2000 / portTICK_PERIOD_MS);
			time(&now);
			localtime_r(&now, &timeinfo);
			if (ppposStatus() != GSM_STATE_CONNECTED) break;
		}
		if (ppposStatus() != GSM_STATE_CONNECTED) {
			sntp_stop();
			ESP_LOGE(TIME_TAG, "Disconnected, waiting for reconnect");
            ESP_LOGE(TIME_TAG, "status is %i" , ppposStatus());
			retry = 0;
			while (ppposStatus() != GSM_STATE_CONNECTED) {
				vTaskDelay(100 / portTICK_RATE_MS);
			}
			continue;
		}

		if (retry < retry_count) {
			ESP_LOGI(TIME_TAG, "TIME SET TO %s", asctime(&timeinfo));
			break;
		}
		else {
			ESP_LOGI(TIME_TAG, "ERROR OBTAINING TIME\n");
		}
		sntp_stop();
		break;
	}


    // Initialize NVS
    esp_err_t ret = nvs_flash_init();
    if (ret == ESP_ERR_NVS_NO_FREE_PAGES || ret == ESP_ERR_NVS_NEW_VERSION_FOUND) {
        ESP_ERROR_CHECK(nvs_flash_erase());
        ret = nvs_flash_init();
    }
    ESP_ERROR_CHECK( ret );
    
    ESP_LOGI(TAG, "Initializing I2C");
    ESP_ERROR_CHECK(i2cdev_init());

    gpio_set_level(LED_PIN, 0);

    get_GPS(); //ADD ERROR CHECK LATER
    vTaskDelay(10000 / portTICK_RATE_MS);
    xTaskCreatePinnedToCore(&aws_iot_task, "aws_iot_task", 9216, NULL, 5, NULL, 1);
}
