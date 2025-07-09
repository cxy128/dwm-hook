#pragma once

#include <Windows.h>
#include <d3d11.h>
#include <string>
#include "imgui.h"
#include "util.h"

#pragma comment(lib, "d3d11.lib")
#pragma comment(lib, "dxgi.lib")
#pragma comment(lib, "dxguid.lib")

#define rgba(x,y,z,w) struct ImVec4(x / 255.0f, y / 255.0f, z / 255.0f, w)

inline bool IsInitFrame = false;

inline ID3D11Device* Device = nullptr;

inline ID3D11Texture2D* BackBuffer = nullptr;

inline ID3D11RenderTargetView* RenderTargetView = nullptr;

inline ID3D11DeviceContext* DeviceContext = nullptr;

// -------------------------------------------------------------

using fnPresentMultiplaneOverlay = __int64(*)(__int64 __this, __int64 SwapChain, int SyncInterval, int Flags, int MetadataType, void* HDRMetadata, void* PresentParameters, int PlaneCount);

inline unsigned __int64 fPresentMultiplaneOverlayAddress = 0;

inline unsigned __int64 fPresentMultiplaneOverlayPatchSize = 0;

inline std::string fPresentMultiplaneOverlayBackupBytes = "";

inline fnPresentMultiplaneOverlay fPresentMultiplaneOverlayTrampoline = nullptr;

// -------------------------------------------------------------

bool Bootstrap();

bool InitFrame(IDXGISwapChain* SwapChain);

void SimulateMouseInputToImGui();

void DrawImGui();

bool InitPresentMultiplaneOverlay();

__int64 fPresentMultiplaneOverlay(__int64 __this, __int64 SwapChain, int SyncInterval, int Flags, int MetadataType, void* HDRMetadata, void* PresentParameters, int PlaneCount);

