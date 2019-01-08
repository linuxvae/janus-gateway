#include "plugin.h"

#include <jansson.h>

#include "../debug.h"
#include "../apierror.h"
#include "../config.h"
#include "../mutex.h"
#include "../record.h"
#include "../rtp.h"
#include "../rtcp.h"
#include "../sdp-utils.h"
#include "../utils.h"

/* Plugin information */
#define JANUS_SRTC_VERSION			6
#define JANUS_SRTC_VERSION_STRING	"0.0.6"
#define JANUS_SRTC_DESCRIPTION		"This is a simple video call plugin for Janus, allowing two WebRTC peers to call each other through a server."
#define JANUS_SRTC_NAME			"JANUS SRTC plugin"
#define JANUS_SRTC_AUTHOR			"Meetecho s.r.l."
#define JANUS_SRTC_PACKAGE			"janus.plugin.videocall"


/* Plugin methods */
janus_plugin *create(void);
int janus_srtc_init(janus_callbacks *callback, const char *config_path);
void janus_srtc_destroy(void);
int janus_srtc_get_api_compatibility(void);
int janus_srtc_get_version(void);
const char *janus_srtc_get_version_string(void);
const char *janus_srtc_get_description(void);
const char *janus_srtc_get_name(void);
const char *janus_srtc_get_author(void);
const char *janus_srtc_get_package(void);
void janus_srtc_create_session(janus_plugin_session *handle, int *error);
struct janus_plugin_result *janus_srtc_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
void janus_srtc_setup_media(janus_plugin_session *handle);
void janus_srtc_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_srtc_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len);
void janus_srtc_incoming_data(janus_plugin_session *handle, char *buf, int len);
void janus_srtc_slow_link(janus_plugin_session *handle, int uplink, int video);
void janus_srtc_hangup_media(janus_plugin_session *handle);
void janus_srtc_destroy_session(janus_plugin_session *handle, int *error);
json_t *janus_srtc_query_session(janus_plugin_session *handle);

/* Plugin setup */
static janus_plugin janus_srtc_plugin =
	JANUS_PLUGIN_INIT (
		.init = janus_srtc_init,
		.destroy = janus_srtc_destroy,

		.get_api_compatibility = janus_srtc_get_api_compatibility,
		.get_version = janus_srtc_get_version,
		.get_version_string = janus_srtc_get_version_string,
		.get_description = janus_srtc_get_description,
		.get_name = janus_srtc_get_name,
		.get_author = janus_srtc_get_author,
		.get_package = janus_srtc_get_package,

		.create_session = janus_srtc_create_session,
		.handle_message = janus_srtc_handle_message,
		.setup_media = janus_srtc_setup_media,
		.incoming_rtp = janus_srtc_incoming_rtp,
		.incoming_rtcp = janus_srtc_incoming_rtcp,
		.incoming_data = janus_srtc_incoming_data,
		.slow_link = janus_srtc_slow_link,
		.hangup_media = janus_srtc_hangup_media,
		.destroy_session = janus_srtc_destroy_session,
		.query_session = janus_srtc_query_session,
	);


janus_plugin *create(void){
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_SRTC_NAME);
	return &janus_srtc_plugin;
}
int janus_srtc_init(janus_callbacks *callback, const char *config_path){
	return 0;
}
void janus_srtc_destroy(void);
int janus_srtc_get_api_compatibility(void){
	return 0;
}
int janus_srtc_get_version(void){
	return 0;
}
const char *janus_srtc_get_version_string(void){
	return NULL;
}
const char *janus_srtc_get_description(void){
	return NULL;
}
const char *janus_srtc_get_name(void){
	return NULL;
}
const char *janus_srtc_get_author(void){
	return NULL;
}
const char *janus_srtc_get_package(void){
	return NULL;
}
void janus_srtc_create_session(janus_plugin_session *handle, int *error){

}
struct janus_plugin_result *
	janus_srtc_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep)
{
	return NULL;
}
void janus_srtc_setup_media(janus_plugin_session *handle){

}
void janus_srtc_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len){

}
void janus_srtc_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len){

}
void janus_srtc_incoming_data(janus_plugin_session *handle, char *buf, int len){

}
void janus_srtc_slow_link(janus_plugin_session *handle, int uplink, int video){

}
void janus_srtc_hangup_media(janus_plugin_session *handle){

}
void janus_srtc_destroy_session(janus_plugin_session *handle, int *error){
	return ;
}
json_t *janus_srtc_query_session(janus_plugin_session *handle){
	return NULL;
}


