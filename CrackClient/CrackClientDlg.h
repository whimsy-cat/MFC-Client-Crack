// CrackClientDlg.h : header file
//

#pragma once
#include <afxinet.h>  // For CInternetSession, CHttpConnection, etc.
#include <ctime>      // For tm
#include <atlconv.h>
#include <atlstr.h>  
#include <string>


// CCrackClientDlg dialog
class CCrackClientDlg : public CDialogEx
{
	// Construction
public:
	CCrackClientDlg(CWnd* pParent = nullptr);	// standard constructor


private:
	// Helper function to URL encode strings
	CString UrlEncode(const CString& str);

	// Member variables for storing username and password
	CString m_strUsername;
	CString m_strpPassword;
	CString credentialToken;
	// Member variable for server end time
	//tm serverEndTime;  // To store and process the server's end time
	//CString endTime;   // For displaying or processing end time in CString format

	// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_CRACKCLIENT_DIALOG };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV support
	// Implementation
protected:
	HICON m_hIcon;

	// Generated message map functions
	virtual BOOL OnInitDialog();
	//virtual void OnClose();
	virtual void OnDestroy();
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()

public:
	tm serverEndTime;
	CString endTime;

	// Button click event handlers
	afx_msg void OnBnClickedQuit();
	afx_msg void OnBnClickedLogin();

	// Timer event handler
	afx_msg void OnTimer(UINT_PTR nIDEvent);


	// Function to send login credentials to the server
	void SendCredentialsToServer(const CString& username, const CString& password);

	void ParseJsonResponse(const CString& response, const CString& username);

	void getEndTimeToServer(const CString& username, const CString& token);
	void ParseJsonForEndTime(const CString& response, const CString& username);

	// Function to notify the server before quitting
	void NotifyServerOnQuit(const CString& username, const CString& token);
};
