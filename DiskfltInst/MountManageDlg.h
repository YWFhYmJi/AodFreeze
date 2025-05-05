#pragma once


// CMountManageDlg dialog

class CMountManageDlg : public CDialog
{
	DECLARE_DYNAMIC(CMountManageDlg)

public:
	CMountManageDlg(CWnd* pParent = nullptr);   // standard constructor
	virtual ~CMountManageDlg();

// Dialog Data
#ifdef AFX_DESIGN_TIME
	enum { IDD = IDD_MOUNTMANAGE };
#endif

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV support

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
	CListCtrl m_mountList;
	afx_msg void OnBnClickedRefreshList();
	afx_msg void OnBnClickedAddMount();
	afx_msg void OnBnClickedDeleteMount();
};
