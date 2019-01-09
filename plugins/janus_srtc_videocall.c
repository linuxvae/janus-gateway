


//点对点的实现
#include "janus_srtc.h"

static srtc_handle_message_pt          srtc_handle_message_next;
static srtc_create_session_pt       srtc_create_session_next;
static srtc_incoming_rtp_pt    srtc_incoming_rtp_next;
static srtc_incoming_rtcp_pt     srtc_incoming_rtcp_next;
static srtc_hangup_media_pt    srtc_hangup_media_next;
static srtc_destroy_session_pt          srtc_destroy_session_next;
static srtc_init_pt 		srtc_init_next;
static srtc_destroy_pt 		srtc_destroy_next;

int janus_srtc_videocall_create_session(janus_plugin_session *handle, int *error){
	return srtc_create_session();

}
int janus_srtc_videocall_destroy_session(janus_plugin_session *handle, int *error){
	return srtc_destroy_session();
}
struct janus_plugin_result *
	janus_srtc_videocall_handle_message(janus_plugin_session *handle, char *transaction, json_t *message, json_t *jsep)
{
	return srtc_handle_message_next(handle, transaction, message, jsep);
}
int janus_srtc_pre_create_plugin(){
	srtc_handle_message_next = srtc_handle_message;
    srtc_handle_message = srtc_handle_message_next;	
	srtc_create_session_next = srtc_create_session;
	srtc_create_session = srtc_create_session_next;
	srtc_destroy_session_next = srtc_destroy_session;
	srtc_destroy_session = srtc_destroy_session_next;
	return 0;
}

