


//进行消息转发：接受到relay信息，+ip和port，进行转发
#include "janus_srtc.h"

static srtc_handle_message_pt          srtc_handle_message_next;
static srtc_create_session_pt       srtc_create_session_next;
static srtc_incoming_rtp_pt    srtc_incoming_rtp_next;
static srtc_incoming_rtcp_pt     srtc_incoming_rtcp_next;
static srtc_hangup_media_pt    srtc_hangup_media_next;
static srtc_destroy_session_pt          srtc_destroy_session_next;
static srtc_init_pt 		srtc_init_next;
static srtc_destroy_pt 		srtc_destroy_next;

static int srtc_module_index = -1;
extern gboolean signal_server;
typedef struct {
	janus_plugin_session *handle;
	void	*websocket_context;
	void 	*callee_info;
	void 	*caller_info;
	janus_refcount ref;
}srtc_relay_message_session_t;


int janus_srtc_relay_create_session(janus_plugin_session *handle, int *error){

	return srtc_create_session(handle, error);

}
int janus_srtc_relay_destroy_session(janus_plugin_session *handle, int *error){
	return srtc_destroy_session(handle, error);
}
struct janus_plugin_result *
	janus_srtc_relay_handle_message(janus_plugin_session *handle, char *transaction, json_t *root, json_t *jsep)
{

	json_t *message = json_object_get(root, "srtc");
	const gchar *message_text = json_string_value(message);

	json_t *relay = json_object_get(root, "relay");

	if(!strcasecmp(message_text, "call")){
		if(relay){
			if(signal_server){//信令服务器处理relay的call 直接通过handle中的session sendmessage 发给B

			}else{//创建session and创建websocket 发送relay成功后destroy/只作为暂时的发送作用

			}

		}else if(signal_server){//创建session and创建websocket  ，查找数据库找到callee IP+port进行relay，callback 发送给handle中的session

		}


	}else if(!strcasecmp(message_text, "accept")){
		if(relay){
			if(signal_server){//找到callee 发送

			}else{//不做什么，由videocall模块去处理accept，他会把acctpt发送给session caller

			}

		}else{//创建session and创建websocket  ，查找数据库通过数据库模块找到callee IP+port进行relay，callback 发送给handle中的session

		}
	}else if(!strcasecmp(message_text, "hangup")){//删除各种连接
		if(relay){
			if(signal_server){//找到callee 发送

			}else{//不做什么，由videocall模块去处理accept，他会把acctpt发送给session caller

			}

		}else{//创建session and创建websocket  ，查找数据库通过数据库模块找到callee IP+port进行relay，callback 发送给handle中的session

		}
	}

	return srtc_handle_message_next(handle, transaction, message, jsep);
}
int janus_srtc__relay_pre_create_plugin(int module_index){
	srtc_handle_message_next = srtc_handle_message;
    srtc_handle_message = srtc_handle_message_next;
	srtc_create_session_next = srtc_create_session;
	srtc_create_session = srtc_create_session_next;
	srtc_destroy_session_next = srtc_destroy_session;
	srtc_destroy_session = srtc_destroy_session_next;
	srtc_module_index = module_index;
	return 0;
}






