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

/* Error codes */
#define JANUS_VIDEOCALL_ERROR_UNKNOWN_ERROR			499
#define JANUS_VIDEOCALL_ERROR_NO_MESSAGE			470
#define JANUS_VIDEOCALL_ERROR_INVALID_JSON			471
#define JANUS_VIDEOCALL_ERROR_INVALID_REQUEST		472
#define JANUS_VIDEOCALL_ERROR_REGISTER_FIRST		473
#define JANUS_VIDEOCALL_ERROR_INVALID_ELEMENT		474
#define JANUS_VIDEOCALL_ERROR_MISSING_ELEMENT		475
#define JANUS_VIDEOCALL_ERROR_USERNAME_TAKEN		476
#define JANUS_VIDEOCALL_ERROR_ALREADY_REGISTERED	477
#define JANUS_VIDEOCALL_ERROR_NO_SUCH_USERNAME		478
#define JANUS_VIDEOCALL_ERROR_USE_ECHO_TEST			479
#define JANUS_VIDEOCALL_ERROR_ALREADY_IN_CALL		480
#define JANUS_VIDEOCALL_ERROR_NO_CALL				481
#define JANUS_VIDEOCALL_ERROR_MISSING_SDP			482
#define JANUS_VIDEOCALL_ERROR_INVALID_SDP			483

typedef struct {
	int srtc_module_index;
	void	*(*srtc_pre_create_plugin_pt) (janus_callbacks *callback, const char *config_path);
	int (*srtc_pre_destroy_plugin_pt) (void*);
	void* mod_ctx;
}srtc_module_t;

extern srtc_module_t* srtc_modules[];

#define srtc_get_module_ctx(module)  (srtc_modules[module.srtc_module_index])->mod_ctx
#define srtc_get_module_session(handle, module) \
	((janus_srtc_session_t*)handle->plugin_handle)->mod_srtc_sessions[module.srtc_module_index]
#define srtc_set_module_session(handle, module, session)  \
	((janus_srtc_session_t*)handle->plugin_handle)->mod_srtc_sessions[module.srtc_module_index] = session;






typedef janus_plugin_result* (*srtc_handle_message_pt)(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);
typedef int (* srtc_create_session_pt)(janus_plugin_session *handle, int *error);
typedef int (* srtc_incoming_rtp_pt)(janus_plugin_session *handle, int video, char *buf, int len);
typedef int (* srtc_incoming_rtcp_pt)(janus_plugin_session *handle, int video, char *buf, int len);
typedef int (* srtc_incoming_data_pt)(janus_plugin_session *handle, char *buf, int len);

typedef int (* srtc_hangup_media_pt)(janus_plugin_session *handle);
typedef int (* srtc_destroy_session_pt)(janus_plugin_session *handle, int *error);
typedef int (* srtc_init_pt)(janus_callbacks *callback, const char *config_path);
typedef	int (* srtc_destroy_pt)(void);

typedef int (*srtc_handle_register_pt)(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep);

typedef struct {
	char* caller_name;
	char* callee_name;
	char* app_key;
	json_t* jsep;
	int  relay;//是否转发到其他服务器
	//有待完善
	char *transaction;
} janus_message_call_t;
typedef	int (* srtc_handle_call_pt)( janus_plugin_session *handle, json_t *message, janus_message_call_t*v);

typedef struct {
	//有待完善
	char* caller_name;
	char* callee_name;
	json_t* jsep;
	int  relay;//是否转发到其他服务器
	char *transaction;
} janus_message_accept_t;
typedef	int (* srtc_handle_accept_pt)( janus_plugin_session *handle, json_t *message, janus_message_accept_t*v);

typedef struct {
	//有待完善
	char *reason;//挂断原因
	char *username;//挂断原因
	int  relay; //是否转发到其他服务器
	char *transaction;
} janus_message_hangup_t;
typedef	int (* srtc_handle_hangup_pt)( janus_plugin_session *handle, json_t *message, janus_message_hangup_t*v);

typedef struct {
	janus_plugin_session *handle;
	void      **mod_srtc_sessions;		//管理各个模块
	volatile gint hangingup;
	volatile gint destroyed;
	janus_refcount ref;
}janus_srtc_session_t;


extern srtc_handle_call_pt		   srtc_handle_call;
extern srtc_handle_accept_pt		   srtc_handle_accept;
extern srtc_handle_hangup_pt		   srtc_handle_hangup;
extern srtc_handle_message_pt          srtc_handle_message;


//以下函数 自己需要用到就自己定义

extern srtc_create_session_pt       srtc_create_session;
extern srtc_incoming_rtp_pt    srtc_incoming_rtp;
extern srtc_incoming_rtcp_pt     srtc_incoming_rtcp;
extern srtc_incoming_data_pt srtc_incoming_data;

extern srtc_hangup_media_pt    srtc_hangup_media;
extern srtc_destroy_session_pt          srtc_destroy_session;
extern srtc_init_pt 	srtc_init;
extern srtc_destroy_pt 	srtc_destroy;

