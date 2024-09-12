#pragma once
#include "afxdialogex.h"


// HomeDialog dialog

class HomeDialog : public CDialogEx
{
	DECLARE_DYNAMIC(HomeDialog)

public:
	HomeDialog(CWnd* pParent = nullptr);   // standard constructor
	virtual ~HomeDialog();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_DIALOG1 };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
};
