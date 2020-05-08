
// HookClientDlg.h: 头文件
//

#pragma once


//
//  Default and Maximum number of threads.
//

//
//  Context passed to worker threads
//

typedef struct _SCANNER_THREAD_CONTEXT {

	HANDLE Port;
	HANDLE Completion;

} SCANNER_THREAD_CONTEXT, *PSCANNER_THREAD_CONTEXT;


const PWSTR ScannerPortName = L"\\ScannerPort";


#define SCANNER_READ_BUFFER_SIZE   1024

typedef struct _SCANNER_NOTIFICATION {

	ULONG BytesToScan;
	ULONG Reserved;             // for quad-word alignement of the Contents structure
	UCHAR Contents[SCANNER_READ_BUFFER_SIZE];

} SCANNER_NOTIFICATION, *PSCANNER_NOTIFICATION;

typedef struct _SCANNER_REPLY {

	BOOLEAN SafeToOpen;

} SCANNER_REPLY, *PSCANNER_REPLY;


//R3->R0的数据结构体
typedef enum _ControlCode {  //控制码
	DEFAULT_CODE,
	ADD_CODE,
	DELETE_CODE,
	CLOSE_CODE,
	OPEN_CODE,
} ControlCode;

typedef struct _Data {
	ControlCode code;
	wchar_t filename[200];

} Data, *PData;

// CHookClientDlg 对话框
class CHookClientDlg : public CDialogEx
{
// 构造
public:
	CHookClientDlg(CWnd* pParent = nullptr);	// 标准构造函数

// 对话框数据
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_HOOKCLIENT_DIALOG };
#endif

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	afx_msg void OnClose();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedOk();
	afx_msg void OnBnClickedCancel();
	afx_msg void OnBnClickedButton1();
};
