/* MDNS-SD Query and advertise Example

   This example code is in the Public Domain (or CC0 licensed, at your option.)

   Unless required by applicable law or agreed to in writing, this
   software is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
   CONDITIONS OF ANY KIND, either express or implied.
*/
#include <string.h>
#include "freertos/FreeRTOS.h"
#include "freertos/task.h"
#include "esp_netif_ip_addr.h"
#include "esp_system.h"
#include "esp_event.h"
#include "esp_log.h"
#include "nvs_flash.h"
#include "esp_netif.h"
#include "protocol_examples_common.h"
#include "mdns.h"
#include "driver/gpio.h"
#include "netdb.h"
#include <sys/socket.h>
#include "freertos/event_groups.h"
#include "esp_wifi.h"
#include "coap3/coap.h"

#define EXAMPLE_MDNS_INSTANCE CONFIG_MDNS_INSTANCE

static const char * TAG = "CoAP_server";
static char * generate_hostname(void);

static void initialise_mdns(void)
{
    char * hostname = generate_hostname();

    //initialize mDNS
    ESP_ERROR_CHECK( mdns_init() );
    //set mDNS hostname (required if you want to advertise services)
    ESP_ERROR_CHECK( mdns_hostname_set(hostname) );
    ESP_LOGI(TAG, "mdns hostname set to: [%s]", hostname);
    //set default mDNS instance name
    ESP_ERROR_CHECK( mdns_instance_name_set(EXAMPLE_MDNS_INSTANCE) );

    //structure with TXT records
    mdns_txt_item_t serviceTxtData[3] = {
        {"board", "esp32"},
        {"u", "user"},
        {"p", "password"}
    };

    //initialize service
    ESP_ERROR_CHECK( mdns_service_add("shoe_control", "_coap", "_udp", 80, serviceTxtData, 3) );

    //add another TXT item
    ESP_ERROR_CHECK( mdns_service_txt_item_set("_coap", "_udp", "path", "/foobar") );
    //change TXT item value
    ESP_ERROR_CHECK( mdns_service_txt_item_set_with_explicit_value_len("_coap", "_udp", "u", "admin", strlen("admin")) );
    free(hostname);
}

#define EXAMPLE_COAP_LOG_DEFAULT_LEVEL CONFIG_COAP_LOG_DEFAULT_LEVEL


static char shoelace[100];
static int shoelace_len = 0;

static char color[100];
static int color_len = 0;

static char pasos[100];
static int pasos_len = 0;

static char talla[100];
static int talla_len = 0;

static char nombre[100];
static int nombre_len = 0;

static int cont_pasos = 0;
static int talla_value = 9;


/*
    Shoelace Handler
*/
static void hnd_shoelace_put(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_pdu_t *request,
                  const coap_string_t *query,
                  coap_pdu_t *response)
{
    size_t size;
    size_t offset;
    size_t total;
    const unsigned char *data;


    if (strcmp (shoelace, "untie") == 0) {
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);
    } else {
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
    }

    /* coap_get_data_large() sets size to 0 on error */
    (void)coap_get_data_large(request, &size, &data, &offset, &total);


    if (size == 0) {      /* re-init */
        snprintf(shoelace, sizeof(shoelace), "untie");
        shoelace_len = strlen(shoelace);
    } else {
        shoelace_len = size > sizeof (shoelace) ? sizeof (shoelace) : size;
        memcpy (shoelace, data, shoelace_len);
    }
    
}

static void hnd_shoelace_get(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_pdu_t *request,
                  const coap_string_t *query,
                  coap_pdu_t *response)
{
   

    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN, 60, 0,
                                 (size_t)shoelace_len,
                                 (const u_char *)shoelace,
                                 NULL, NULL);
}


/*
    Color Handler
*/
static void hnd_color_put(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_pdu_t *request,
                  const coap_string_t *query,
                  coap_pdu_t *response)
{
    size_t size;
    size_t offset;
    size_t total;
    const unsigned char *data;
    
    if (strcmp (color, "000000") == 0) {
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);
    } else {
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
    }

    /* coap_get_data_large() sets size to 0 on error */
    (void)coap_get_data_large(request, &size, &data, &offset, &total);

    if (size == 0) {      /* re-init */
        snprintf(color, sizeof(color), "000000");
        color_len = strlen(color);
    } else {
        color_len = size > sizeof (color) ? sizeof (color) : size;
        memcpy (color, data, color_len);
    }
}

static void hnd_color_get(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_pdu_t *request,
                  const coap_string_t *query,
                  coap_pdu_t *response)
{
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN, 60, 0,
                                 (size_t)color_len,
                                 (const u_char *)color,
                                 NULL, NULL);
}


static void hnd_color_delete(coap_resource_t *resource,
                     coap_session_t *session,
                     const coap_pdu_t *request,
                     const coap_string_t *query,
                     coap_pdu_t *response)
{
    snprintf(color, sizeof(color), "000000");
    color_len = strlen(color);
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_DELETED);
}

/*
    Pasos Handler
*/
static void hnd_pasos_get(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_pdu_t *request,
                  const coap_string_t *query,
                  coap_pdu_t *response)
{
    itoa(cont_pasos, pasos, 10);
    pasos_len = strlen(pasos);
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);

    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN, 60, 0,
                                 (size_t)pasos_len,
                                 (const u_char *)pasos,
                                 NULL, NULL);
}

static void hnd_pasos_delete(coap_resource_t *resource,
                     coap_session_t *session,
                     const coap_pdu_t *request,
                     const coap_string_t *query,
                     coap_pdu_t *response)
{
    cont_pasos = 0;
    snprintf(pasos, sizeof(pasos), "0");
    pasos_len = strlen(pasos);
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_DELETED);
    
}

/*
    Tamaño Handler
*/
static void hnd_talla_get(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_pdu_t *request,
                  const coap_string_t *query,
                  coap_pdu_t *response)

{
    itoa(talla_value, talla, 10);
    pasos_len = strlen(talla);
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN, 60, 0,
                                 (size_t)talla_len,
                                 (const u_char *)talla,
                                 NULL, NULL);
}

/*
    Nombre Handler
*/
static void hnd_nombre_put(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_pdu_t *request,
                  const coap_string_t *query,
                  coap_pdu_t *response)
{
    size_t size;
    size_t offset;
    size_t total;
    const unsigned char *data;

    if (strcmp (nombre, "Empty") == 0) {
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_CREATED);
    } else {
        coap_pdu_set_code(response, COAP_RESPONSE_CODE_CHANGED);
    }

    /* coap_get_data_large() sets size to 0 on error */
    (void)coap_get_data_large(request, &size, &data, &offset, &total);


    if (size == 0) {      /* re-init */
        snprintf(nombre, sizeof(nombre), "Empty");
        nombre_len = strlen(nombre);
    } else {
        nombre_len = size > sizeof (nombre) ? sizeof (nombre) : size;
        //memcpy (nombre, data, nombre_len);
        strncpy(nombre, (const char *)data, 100);
    }
}




static void hnd_nombre_get(coap_resource_t *resource,
                  coap_session_t *session,
                  const coap_pdu_t *request,
                  const coap_string_t *query,
                  coap_pdu_t *response)
{
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_CONTENT);
    coap_add_data_large_response(resource, session, request, response,
                                 query, COAP_MEDIATYPE_TEXT_PLAIN, 60, 0,
                                 (size_t)nombre_len,
                                 (const u_char *)nombre,
                                 NULL, NULL);
}



static void hnd_nombre_delete(coap_resource_t *resource,
                     coap_session_t *session,
                     const coap_pdu_t *request,
                     const coap_string_t *query,
                     coap_pdu_t *response)
{
    snprintf(nombre, sizeof(nombre), " ");
    nombre_len = strlen(nombre);
    coap_pdu_set_code(response, COAP_RESPONSE_CODE_DELETED);
}


void coap_log_handler (coap_log_t level, const char *message)
{
    uint32_t esp_level = ESP_LOG_INFO;
    char *cp = strchr(message, '\n');

    if (cp)
        ESP_LOG_LEVEL(esp_level, TAG, "%.*s", (int)(cp-message), message);
    else
        ESP_LOG_LEVEL(esp_level, TAG, "%s", message);
}

static void coap_example_server(void *p)
{
    coap_context_t *ctx = NULL;
    coap_address_t serv_addr;
    coap_resource_t *resource_shoelace = NULL;
    coap_resource_t *resource_color = NULL;
    coap_resource_t *resource_pasos = NULL;
    coap_resource_t *resource_talla = NULL;
    coap_resource_t *resource_nombre = NULL;

    snprintf(shoelace, sizeof(shoelace), "untie");
    shoelace_len = strlen(shoelace);
    snprintf(color, sizeof(color), "000000");
    color_len = strlen(color);
    snprintf(pasos, sizeof(pasos), "0");
    pasos_len = strlen(pasos);
    snprintf(talla, sizeof(talla), "9");
    talla_len = strlen(talla);
    snprintf(nombre, sizeof(nombre), " ");
    nombre_len = strlen(nombre);

    coap_set_log_handler(coap_log_handler);
    coap_set_log_level(EXAMPLE_COAP_LOG_DEFAULT_LEVEL);

    ESP_LOGI(TAG, "CoAP server example started!");

    while (1) {
        coap_endpoint_t *ep = NULL;
        unsigned wait_ms;

        /* Prepare the CoAP server socket */
        coap_address_init(&serv_addr);
        serv_addr.addr.sin6.sin6_family = AF_INET6;
        serv_addr.addr.sin6.sin6_port   = htons(COAP_DEFAULT_PORT);

        ctx = coap_new_context(NULL);
        if (!ctx) {
            ESP_LOGE(TAG, "coap_new_context() failed");
            continue;
        }
        coap_context_set_block_mode(ctx,
                                    COAP_BLOCK_USE_LIBCOAP|COAP_BLOCK_SINGLE_BODY);

        ep = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_UDP);
        if (!ep) {
            ESP_LOGE(TAG, "udp: coap_new_endpoint() failed");
            goto clean_up;
        }
        ep = coap_new_endpoint(ctx, &serv_addr, COAP_PROTO_TCP);
        if (!ep) {
            ESP_LOGE(TAG, "tcp: coap_new_endpoint() failed");
            goto clean_up;
        }

        /* 
        Recursos y request de las URIs
        */
        resource_shoelace = coap_resource_init(coap_make_str_const("shoe/shoelace"), 0);
        if (!resource_shoelace) {
            ESP_LOGE(TAG, "coap_resource_init() failed");
            goto clean_up;
        }
        coap_register_handler(resource_shoelace, COAP_REQUEST_PUT, hnd_shoelace_put);
        coap_register_handler(resource_shoelace, COAP_REQUEST_GET, hnd_shoelace_get);
        coap_add_resource(ctx, resource_shoelace);

        resource_color = coap_resource_init(coap_make_str_const("shoe/ledcolor"), 0);
        if (!resource_color) {
            ESP_LOGE(TAG, "coap_resource_init() failed");
            goto clean_up;
        }
        coap_register_handler(resource_color, COAP_REQUEST_PUT, hnd_color_put);
        coap_register_handler(resource_color, COAP_REQUEST_GET, hnd_color_get);
        coap_register_handler(resource_color, COAP_REQUEST_DELETE, hnd_color_delete);
        coap_add_resource(ctx, resource_color);

        resource_pasos = coap_resource_init(coap_make_str_const("shoe/steps"), 0);
        if (!resource_pasos) {
            ESP_LOGE(TAG, "coap_resource_init() failed");
            goto clean_up;
        }
        coap_register_handler(resource_pasos, COAP_REQUEST_GET, hnd_pasos_get);
        coap_register_handler(resource_pasos, COAP_REQUEST_DELETE, hnd_pasos_delete);
        coap_add_resource(ctx, resource_pasos);
        
        resource_talla = coap_resource_init(coap_make_str_const("shoe/size"), 0);
        if (!resource_talla) {
            ESP_LOGE(TAG, "coap_resource_init() failed");
            goto clean_up;
        }
        coap_register_handler(resource_talla, COAP_REQUEST_GET, hnd_talla_get);
        coap_add_resource(ctx, resource_talla);

        resource_nombre = coap_resource_init(coap_make_str_const("shoe/name"), 0);
        if (!resource_nombre) {
            ESP_LOGE(TAG, "coap_resource_init() failed");
            goto clean_up;
        }
        coap_register_handler(resource_nombre, COAP_REQUEST_PUT, hnd_nombre_put);
        coap_register_handler(resource_nombre, COAP_REQUEST_GET, hnd_nombre_get);
        coap_register_handler(resource_nombre, COAP_REQUEST_DELETE, hnd_nombre_delete);
        coap_add_resource(ctx, resource_nombre);

        

        wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;

        while (1) {
        if(cont_pasos < 1000){
            cont_pasos = cont_pasos + 1;
        } else{
            cont_pasos = 0;
        }
            
            int result = coap_io_process(ctx, wait_ms);
            if (result < 0) {
                break;
            } else if (result && (unsigned)result < wait_ms) {
                /* decrement if there is a result wait time returned */
                wait_ms -= result;
            }
            if (result) {
                /* result must have been >= wait_ms, so reset wait_ms */
                wait_ms = COAP_RESOURCE_CHECK_TIME * 1000;
            }

            vTaskDelay(50 / portTICK_PERIOD_MS);
            
        }
    }
clean_up:
    coap_free_context(ctx);
    coap_cleanup();

    vTaskDelete(NULL);
}

/*
mDNS initialization
*/
void app_main(void)
{
    ESP_ERROR_CHECK(nvs_flash_init());
    ESP_ERROR_CHECK(esp_netif_init());
    ESP_ERROR_CHECK(esp_event_loop_create_default());

    initialise_mdns();

    /* This helper function configures Wi-Fi or Ethernet, as selected in menuconfig.
     * Read "Establishing Wi-Fi or Ethernet Connection" section in
     * examples/protocols/README.md for more information about this function.
     */
    ESP_ERROR_CHECK(example_connect());

    xTaskCreate(&coap_example_server, "coap_example_server",  8 * 1024, NULL, 5, NULL);
}

/** Generate host name based on sdkconfig, optionally adding a portion of MAC address to it.
 *  @return host name string allocated from the heap
 */
static char* generate_hostname(void)
{
#ifndef CONFIG_MDNS_ADD_MAC_TO_HOSTNAME
    return strdup(CONFIG_MDNS_HOSTNAME);
#else
    uint8_t mac[6];
    char   *hostname;
    esp_read_mac(mac, ESP_MAC_WIFI_STA);
    if (-1 == asprintf(&hostname, "%s-%02X%02X%02X", CONFIG_MDNS_HOSTNAME, mac[3], mac[4], mac[5])) {
        abort();
    }
    return hostname;
#endif
}
