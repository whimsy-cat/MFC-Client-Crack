
// CrackClientDlg.h : header file
//

#pragma once


// CCrackClientDlg dialog
class CCrackClientDlg : public CDialogEx
{
// Construction
public:
	CCrackClientDlg(CWnd* pParent = nullptr);	// standard constructor
	CString str_userName;
	CString str_passWord;
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
	afx_msg void OnSysCommand(UINT nID, LPARAM lParam);
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedQuit();
	afx_msg void OnBnClickedLogin();
};
