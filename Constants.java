package com.fedex.apac.esd.common.util;

/**
 *
 *
 * @author Qiao Guo Jun
 * @date 21 Oct 2010
 * @version 1.0.1.0
 */
public class Constants {

	// Audit type.
	public static final char AUDIT_STATUS_TYPE_ERROR = 'E';
	public static final char AUDIT_STATUS_TYPE_INFO = 'I';
	public static final char AUDIT_STATUS_TYPE_WARNING = 'W';
	// Audit status
	public static final char AUDIT_STATUS_SUCCESS = 'S';
	public static final char AUDIT_STATUS_FAIL = 'F';
	// audit system user
	public static final String AUDIT_SYS_ADMIN = "SYSADMIN";

	// audit for web service
	public static final String AUDIT_AUTH = "AUTH";
	public static final String AUDIT_AUTH_SYSTEM = "SYSTEM";
	public static final String AUDIT_WS_CLIENT = "AUTH_WS_CLIENT";
	public static final String AUDIT_WS_SERVER = "AUTH_WS_SERVER";
	public static final String AUTH_WEEKLY_REPORT = "AUTH_WEEKLY_REPORT";
	public static final char AUDIT_AUTH_SUCCESS = 'S';
	public static final char AUDIT_AUTH_FAILED = 'F';

	// Audit type code
	public static final char AUDIT_TYPE_CODE_IMPORTING = 'I';
	public static final char AUDIT_TYPE_CODE_SHIPPING = 'S';
	public static final char AUDIT_TYPE_CODE_REPORTING = 'R';
	public static final char AUDIT_TYPE_CODE_PREPROCESS = 'P';
	public static final char AUDIT_TYPE_CODE_OUTBOUND = 'Y';
	public static final char AUDIT_TYPE_CODE_INBOUND = 'X';
	public static final String AUDIT_SHIPPING_LOG_HEADER = "H";
	public static final char AUDIT_TYPE_CODE_COMMON = 'C';

	public static final String AUDIT_ARCHIVING = "Archive";
	public static final char AUDIT_TYPE_CODE_ARCHIVING = 'A';

	public static final String AUDIT_MONTHLY_REPORT = "Monthly_Report";

	public static final String none = "";
	public static final String zero = "0";
	public static final String select = "Select";

	// Default rows per page
	public static final String DEFAULT_ROWS_PER_PAGE = "20";

	public static final String STR_ADD = "Add";
	public static final String STR_EDIT = "Edit";

	public static final String STR_PRINTER_PROFILE_ID = "printerProfileId";

	public static final String STR_ERROR_MESSAGE = "errorMessage";
	public static final String STR_SUCCESS_MESSAGE = "successedMessage";
	public static final String STR_SUCCESS_PANEL = "successedPanel";

	// Required indicator
	public static final String STR_REQUIRED = "* ";

	// Query
	public static final String OPEN_PARENTHESIS = "(";
	public static final String CLOSE_PARENTHESIS = ")";

	public static final String FILE_SEPARATE = "/";

	// Report Type
	public static final String RPT_DAILY_SHIPMENT = "DAILY";
	public static final String RPT_MONTHLY_SHIPMENT = "MONTHLY";
	public static final String RPT_SHIPMENT = "SHIPMENT";
	public static final String RPT_SHIPMENT_ETD = "SHIPMENT_ETD";
	public static final String RPT_IMPORTERDTO = "IMPORTERDTO";
	public static final String RPT_BOOKING = "BOOKING";
	public static final String RPT_SCHEDULED = "SCHEDULED";
	public static final String RPT_DATE_TIME_RANGE = "DATE_TIME_RANGE";
	public static final String RPT_REPORT = "REPORT";
	public static final String RPT_CUSTOMIZED = "CUSTOMIZED";

	public static final String RPT_DAILY = "DAILY";
	public static final String RPT_WEEKLY = "WEEKLY";
	public static final String RPT_MONTHLY = "MONTHLY";

	public static final char EVENT_TYPE_REPORT_CD = 'R';
	public static final char EVENT_TYPE_NOTIFICATION_CD = 'N';

	public static final String EVENT_TYPE_REPORT_VALUE = "Report";
	public static final String EVENT_TYPE_NOTIFICATION_VALUE = "Notification";

	public static final String APP_TYPE_COMMON_CD = "CM";
	public static final String APP_TYPE_SHIPPING_CD = "SH";
	public static final String APP_TYPE_ORDER_PROCESSOR_CD = "OP";

	public static final String APP_TYPE_COMMON_VALUE = "Common";
	public static final String APP_TYPE_SHIPPING_VALUE = "Shipping";
	public static final String APP_TYPE_ORDER_PROCESSOR_VALUE = "Order Processor";

	public static final String hostname = "hostname";
	public static final String configured_email_notification_file = "email.notification.file";
	public static final String configured_email_notification_url = "email.notification.url";
	public static final String configured_email_notification_shipper = "email.notification.shipper";
	public static final String ecshipping_wsdl_url = "ecshipping.ws.url";
	public static final String ws_security_ip = "ws.security.ip";
	public static final String YES = "Y";

	public static final String configured_label_notification_file = "label.notification.file";

	public static final String FileUploadedBy = "FileUploadedBy";

	public static final String CI_DOCUMENT_OPT_IDENTIFIER = "CI_DOCUMENT_UPLOAD_PATH";

	public static final String customized_label_Package_count = "package.label.count";
	
	public static final String shipment_confirm_evnet_email = "shipment.confirm.event.email";
	
	public final static String  UploadOPFileFlag = "UploadOPFileFlag";
	public final static String ImporterShippingMode = "ImporterShippingMode";
	public final static String ImporterShippingMode_ForwardTo_InProgress = "ImporterShippingMode_ForwardTo_InProgress";
	
	public final static String romanizedRequired = "romanizedRequired";//for local language
	public final static String SH_TransactionId = "SH.TransactionId"; //Merge Labels in Shipment History, it must put into shipmentOptional tabel with identifier#file_request_id, value#{Original filename}
	public final static String shipping_transaction_sequence = "shipping_transaction_sequence";//Merge Labels in Shipment History, it must put into shipmentOptional tabel with identifier#file_request_seq, value#{logic for customer}
	public final static String shipping_transaction_result = "shipping_transaction_result";//optional, mapped to request, request-response.
	public final static String shipping_transaction_success = "Success";
	public final static String shipping_transaction_failed = "Failure";
 
	
	public final static String sortby_shipping_transaction_sequence = "sortby.shipping.transaction.sequence";//Merge Labels in Shipment History, optional, original sequence in original request.
	
	public final static String fedex_tracking_link = "http://www.fedex.com/Tracking?tracknumbers="; //fedex tracking hyperlink
	
	public final static String default_merge_label_size = "default.merge.label.size";
	
	public static final String LabelConfigureSameAsOtherAccount = "Label.Configure.SameAs.OtherAccount";
	public static final String LabelConfigureSameAsOtherAccountComments = "This account label configuration same as configured account";
	
	//apply default to all pages if no defined property in account level.
	public static final String Paginator_Setting_Default = "Paginator.Setting.Default";//default is set to 30
	public static final String Paginator_Setting = "Paginator.Setting";
	
	//initila fix page size for particular 4 pages, it can be overrided by Paginator.Setting
	public static final String Paginator_Setting_Fixed = "Paginator.Setting.Fixed";
	
	public static final String PoolSetting_Core = "ecthreadpoolexecutor.corepoolsize";//for importer
	public static final String PoolSetting_Max = "ecthreadpoolexecutor.maxpoolsize";//for importer
	
	public static final String PoolSetting_Shipping_Core = "ecthreadpoolexecutor.corepoolsize.ship";//for ship shipments
	public static final String PoolSetting_Shipping_Max = "ecthreadpoolexecutor.maxpoolsize.ship";//for ship shipments
	
	public static final String PoolSetting_WSShipping_Core = "ecthreadpoolexecutor.corepoolsize.ship.ws";//for ship shipments with web service
	public static final String PoolSetting_WSShipping_Max = "ecthreadpoolexecutor.maxpoolsize.ship.ws";//for ship shipments with web service
	
	public static final String PoolSetting_FXRS_IP_UseLatch4IP = "ecthreadpoolexecutor.corepoolsize.ship.ip.fxrs.uselatch4ip";//for FXRS connect controlling.
	public static final String PoolSetting_FXRS_IPCore = "ecthreadpoolexecutor.corepoolsize.ship.ip.fxrs";//for FXRS connect controlling.
	public static final String PoolSetting_FXRS_IPMax = "ecthreadpoolexecutor.maxpoolsize.ship.ip.fxrs";//for FXRS connect controlling.
	
	public static final String PoolSetting_FXRS_IPDCore = "ecthreadpoolexecutor.corepoolsize.ship.ipd.fxrs";//for FXRS connect controlling.
	public static final String PoolSetting_FXRS_IPDMax = "ecthreadpoolexecutor.maxpoolsize.ship.ipd.fxrs";//for FXRS connect controlling.
	
	
	public static final String PoolSetting_FXRSSocket_Max = "ecthreadpoolexecutor.maxpoolsize.fxrs.socket";//for ship shipments
	
	public static final String[] SpecialWordSetLabelByDefault = { "\\", "$", "."};
	public static final String SpecialWordSetLabel = "Special.WordSet.Label"; 
	public static final String SpecialWordSetCommodity = "Special.WordSet.Commodity"; 
	public static final String SpecialWordSetCommodityDescToTrimOrToEmpty = "Special.WordSet.CommodityDescToTrimOrToEmpty"; 

	public static final String SeleniumSorting = "selenium.sorting";
	public static boolean seleniumSortingFlag = false;
	
	public static final String EC_ServerNode_Agent_Process = "server.node.agent.process";
	public static final String EC_ServerNode = "server.node";
	
	public static final String EC_Env_LB_Servere = "env.lb.server";
	
	public static final String REMOVE_SPECIAL_CHARS = "SH.REMOVE.SPECIAL.CHARS";
	public final static String HTTP_PROXY_SERVER = "eula.http.proxy.server";
	public final static String HTTP_PROXY_PORT = "eula.http.proxy.port";
	public final static String HTTP_PROXY_DISABLED = "eula.http.proxy.disabled";
	public static final String AES_ENCRYPTION_KEY = "aes.encryption.key";
	
	/**
	 * defined error list.
	 */
	public static String ERR001 = "ERR001";
	public static String ERR002 = "ERR002";
	public static String ERR003 = "ERR003";
	public static String ERR004 = "ERR004";
	public static String ERR005 = "ERR005";
	public static String ERR006 = "ERR006";
	public static String ERR007 = "ERR007";
	public static String ERR008 = "ERR008";
	public static String ERR008_Error_Message = "Carton(s) is in progress.";
	public static String ERR009 = "ERR009";
	public static String ERR010 = "ERR010";
	
	public static String ERR011 = "ERR011";
}
