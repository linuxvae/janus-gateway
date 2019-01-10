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



typedef struct {
	int srtc_module_index;
	void	*(*srtc_pre_create_plugin_pt) ();
	int (*srtc_pre_destroy_plugin_pt) ();
	void* mod_ctx;
}srtc_module_t;

extern srtc_module_t srtc_modules[];

#define srtc_get_module_ctx(module)  srtc_modules[module.srtc_module_index]


typedef janus_plugin_result* (*srtc_handle_message_pt)(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
typedef int (* srtc_create_session_pt)(janus_plugin_session *handle, int *error);
typedef int (* srtc_incoming_rtp_pt)(janus_plugin_session *handle, int video, char *buf, int len);
typedef int (* srtc_incoming_rtcp_pt)(janus_plugin_session *handle, int video, char *buf, int len);
typedef int (* srtc_hangup_media_pt)(janus_plugin_session *handle);
typedef int (* srtc_destroy_session_pt)(janus_plugin_session *handle, int *error);
typedef int (* srtc_init_pt)(janus_callbacks *callback, const char *config_path);
typedef	int (* srtc_destroy_pt)(void);


typedef struct {
	char* caller_name;
	char* callee_name;
	char* app_key;
	//有待完善
	
} janus_message_call_t;

typedef	int (* srtc_handle_call_pt)( janus_plugin_session *handle, janus_message_call_t*v);




typedef struct {
	janus_plugin_session *handle;
	void      **mod_srtc_ctx;		//管理各个模块
	janus_refcount ref;
}janus_srtc_session_t;

extern srtc_handle_message_pt          srtc_handle_message;
extern srtc_create_session_pt       srtc_create_session;
extern srtc_incoming_rtp_pt    srtc_incoming_rtp;
extern srtc_incoming_rtcp_pt     srtc_incoming_rtcp;
extern srtc_hangup_media_pt    srtc_hangup_media;
extern srtc_destroy_session_pt          srtc_destroy_session;
extern srtc_init_pt srtc_init;
extern srtc_destroy_pt srtc_destroy;

