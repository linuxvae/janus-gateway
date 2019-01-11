#include "janus_srtc.h"

/* Plugin information */
#define JANUS_SRTC_VERSION			6
#define JANUS_SRTC_VERSION_STRING	"0.0.6"
#define JANUS_SRTC_DESCRIPTION		"This is a simple video call plugin for Janus, allowing two WebRTC peers to call each other through a server."
#define JANUS_SRTC_NAME			"JANUS SRTC plugin"
#define JANUS_SRTC_AUTHOR			"Meetecho s.r.l."
#define JANUS_SRTC_PACKAGE			"janus.plugin.videocall"


srtc_handle_call_pt          srtc_handle_call;
srtc_handle_accept_pt          srtc_handle_accept;
srtc_handle_hangup_pt          srtc_handle_hangup;



srtc_handle_message_pt          srtc_handle_message;
srtc_create_session_pt       srtc_create_session;
srtc_incoming_rtp_pt    srtc_incoming_rtp;
srtc_incoming_rtcp_pt     srtc_incoming_rtcp;
srtc_hangup_media_pt    srtc_hangup_media;
srtc_destroy_session_pt          srtc_destroy_session;
srtc_init_pt							srtc_init;
srtc_destroy_pt						srtc_destroy;

static int srtc_module_index = -1;//可以作成一个结构体



/* Plugin methods */
janus_plugin *create(void);
int janus_srtc_init(janus_callbacks *callback, const char *config_path);
void janus_srtc_destroy(void);
int janus_srtc_get_api_compatibility(void);
int janus_srtc_get_version();
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


extern  srtc_module_t srtc_rlay_msg_module;
srtc_module_t srtc_core_module;

srtc_module_t* srtc_modules[]={&srtc_core_module, &srtc_rlay_msg_module};//简单的方法加载各个模块
int janus_max_srtc_module = sizeof(srtc_modules)/sizeof(srtc_module_t*);

janus_plugin *create(void){
	JANUS_LOG(LOG_VERB, "%s created!\n", JANUS_SRTC_NAME);

	return &janus_srtc_plugin;
}
int janus_srtc_init(janus_callbacks *callback, const char *config_path){
	int i=0;
	for(;i<janus_max_srtc_module;i++){
		srtc_modules[i]->mod_ctx = srtc_modules[i]->srtc_pre_create_plugin_pt(config_path);
		srtc_modules[i]->srtc_module_index = i;
	}
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
int
	janus_srtc_handle_call_init(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep)
{
	static janus_message_call_t  v;
	//解析message 后生成V todo

	return srtc_handle_call( handle, message, &v);
}

struct janus_plugin_result *
	janus_srtc_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep)
{
	json_t *srtc = json_object_get(message, "srtc");
	const gchar *message_text = json_string_value(srtc);
	if(!strcasecmp(message_text, "call")){
		janus_srtc_handle_call_init(handle, transaction, message, jsep);
	}//有待继续添加其他
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

//******core_module*********
void* janus_srtc_core_create_plugin(const char *config_path);

srtc_module_t srtc_core_module = {
	0,
	janus_srtc_core_create_plugin,
	NULL,
	NULL
};
typedef struct {
	//存储相关模块的配置信息
}srtc_core_ctx_t;

static int
	janus_srtc_core_handle_call(janus_plugin_session *handle, json_t *message, janus_message_call_t *v)
{
	return 0;
}
static int
	janus_srtc_core_handle_accept(janus_plugin_session *handle, json_t *message, janus_message_accept_t *v)
{
	return 0;
}

static int
	janus_srtc_core_handle_hangup(janus_plugin_session *handle, json_t *message, janus_message_hangup_t *v)
{
	return 0;
}
static int janus_srtc_core_incoming_rtp(janus_plugin_session *handle, int video, char *buf, int len){
		return srtc_incoming_rtp(handle, video, buf,len);

}
static int janus_srtc_core_incoming_rtcp(janus_plugin_session *handle, int video, char *buf, int len){
	return srtc_incoming_rtcp(handle, video, buf,len);

}
void* janus_srtc_core_create_plugin(const char *config_path){
	srtc_handle_call = janus_srtc_core_handle_call;
	srtc_handle_accept = janus_srtc_core_handle_accept;
	srtc_handle_hangup = janus_srtc_core_handle_hangup;
	srtc_incoming_rtp = janus_srtc_core_incoming_rtp;
	srtc_incoming_rtcp = janus_srtc_core_incoming_rtcp;
	srtc_core_ctx_t *ctx =(srtc_core_ctx_t*)g_malloc(sizeof(srtc_core_ctx_t));
	return ctx;
}



