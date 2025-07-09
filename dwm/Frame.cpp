#include "Frame.h"
#include "imgui_impl_win32.h"
#include "imgui_impl_dx11.h"

bool Bootstrap() {

	return InitPresentMultiplaneOverlay();
}

bool InitFrame(IDXGISwapChain* SwapChain) {

	if (IsInitFrame) {
		return true;
	}

	auto ProgmanHwnd = FindWindowA("Progman", "Program Manager");
	if (!ProgmanHwnd) {
		return false;
	}

	auto Status = SwapChain->GetDevice(__uuidof(ID3D11Device), reinterpret_cast<void**>(&Device));
	if (FAILED(Status)) {
		return false;
	}

	Status = SwapChain->GetBuffer(0, __uuidof(ID3D11Texture2D), reinterpret_cast<void**>(&BackBuffer));
	if (FAILED(Status)) {
		return false;
	}

	Status = Device->CreateRenderTargetView(BackBuffer, nullptr, &RenderTargetView);
	if (FAILED(Status)) {
		return false;
	}

	Device->GetImmediateContext(&DeviceContext);

	ImGui::CreateContext();

	auto& Io = ImGui::GetIO();
	Io.ConfigFlags |= ImGuiConfigFlags_NoMouseCursorChange;
	Io.Fonts->AddFontFromFileTTF("C:\\Windows\\Fonts\\msyh.ttc", 22.0f, nullptr, Io.Fonts->GetGlyphRangesChineseFull());

	auto& Style = ImGui::GetStyle();
	Style.WindowRounding = 8.0f;
	Style.FrameRounding = 5.0f;

	ImGui::StyleColorsDark();

	ImVec4* colors = Style.Colors;
	colors[ImGuiCol_WindowBg] = rgba(44.0f, 62.0f, 80.0f, 1.0f);

	ImGui_ImplWin32_Init(ProgmanHwnd);

	ImGui_ImplDX11_Init(Device, DeviceContext);

	IsInitFrame = true;

	return true;
}

void SimulateMouseInputToImGui() {

	POINT Point = {};
	if (!GetCursorPos(&Point)) {
		return;
	}

	HWND hWnd = GetActiveWindow();
	if (hWnd) {
		ScreenToClient(hWnd, &Point);
	}

	ImGuiIO& io = ImGui::GetIO();

	io.ConfigFlags |= ImGuiConfigFlags_NavEnableSetMousePos;
	io.MousePos = ImVec2((float)Point.x, (float)Point.y);

	io.MouseDown[0] = (GetAsyncKeyState(VK_LBUTTON) & 0x8000) != 0;
	io.MouseDown[1] = (GetAsyncKeyState(VK_RBUTTON) & 0x8000) != 0;
	io.MouseDown[2] = (GetAsyncKeyState(VK_MBUTTON) & 0x8000) != 0;

	SHORT wheelDelta = GET_WHEEL_DELTA_WPARAM(GetMessageExtraInfo());
	io.MouseWheel = wheelDelta / (float)WHEEL_DELTA;
}

void DrawImGui() {

	ImGui_ImplDX11_NewFrame();
	ImGui_ImplWin32_NewFrame();

	ImGui::NewFrame();

	{
		ImGui::Begin("ImGui", nullptr, ImGuiWindowFlags_NoTitleBar);

		ImGuiIO& io = ImGui::GetIO();;
		ImGui::Text("Application average %.3f ms/frame (%.1f FPS)", 1000.0f / io.Framerate, io.Framerate);

		ImGui::End();
	}

	ImGui::EndFrame();

	ImGui::Render();

	DeviceContext->OMSetRenderTargets(1, &RenderTargetView, nullptr);

	ImGui_ImplDX11_RenderDrawData(ImGui::GetDrawData());
}

bool InitPresentMultiplaneOverlay() {

	// 虚拟机 Windows 11 23H2 --> DrawingContext::PresentDWM
	// #  Call Site
	// 00 d2d1!DrawingContext::PresentDWM
	// 01 d2d1!D2DDeviceContextBase<ID2D1BitmapRenderTarget, ID2D1BitmapRenderTarget, ID2D1DeviceContext7>::PresentDWM + 0xc9
	// 02 dwmcore!CD3DDevice::Present + 0x7f
	// 03 dwmcore!CLegacySwapChain::Present + 0x8c
	// 04 dwmcore!COverlayContext::Present + 0x10b
	// 05 dwmcore!CLegacyRenderTarget::Present + 0x12f
	// 06 dwmcore!CRenderTargetManager::Present + 0x77
	// 07 dwmcore!CComposition::Present + 0x57
	// 08 dwmcore!CPartitionVerticalBlankScheduler::PresentFrame + 0x8b
	// 09 dwmcore!CPartitionVerticalBlankScheduler::ProcessFrame + 0x1a6
	// 0a dwmcore!CPartitionVerticalBlankScheduler::ScheduleAndProcessFrame + 0xb2
	// 0b dwmcore!CConnection::MainCompositionThreadLoop + 0xb7
	// 0c dwmcore!CConnection::RunCompositionThread + 0xf5
	// 0d KERNEL32!BaseThreadInitThunk + 0x1d
	// 0e ntdll!RtlUserThreadStart + 0x28

	// ------------------------------------------------------------------------------------------

	// 物理机 Windows 11 23H2 --> DrawingContext::PresentMultiplaneOverlay

	auto ModuleAddress = reinterpret_cast<unsigned __int64>(GetModuleHandleA("d2d1.dll"));
	if (!ModuleAddress) {
		return false;
	}

	// 8A 01 88 84 24 ?? ?? ?? ?? 8A 84 24 ?? ?? ?? ?? 8B 84 24 ?? ?? ?? ?? 
	unsigned char Bytes[] = {
		 0x8A ,0x01 ,
		 0x88 ,0x84 ,0x24 ,0x00 ,0x00 ,0x00 ,0x00 ,
		 0x8A ,0x84 ,0x24 ,0x00 ,0x00 ,0x00 ,0x00 ,
		 0x8B ,0x84 ,0x24 ,0x00 ,0x00 ,0x00 ,0x00
	};

	auto Address = SearchSignature(ModuleAddress, Bytes, ".text", "xxxxx????xxx????xxx????");
	if (!Address) {
		return false;
	}

	auto Offset = *reinterpret_cast<__int32*>(Address + 1 + 0x3B);

	fPresentMultiplaneOverlayAddress = Address + 5 + 0x3B + Offset;

	fPresentMultiplaneOverlayPatchSize = GetDestroyInstructionLength(fPresentMultiplaneOverlayAddress);
	if (!fPresentMultiplaneOverlayPatchSize) {
		return false;
	}

	return PatchAddress(fPresentMultiplaneOverlayAddress, &fPresentMultiplaneOverlayTrampoline, fPresentMultiplaneOverlay, fPresentMultiplaneOverlayBackupBytes, fPresentMultiplaneOverlayPatchSize);
}

__int64 fPresentMultiplaneOverlay(__int64 __this, __int64 SwapChain, int SyncInterval, int Flags, int MetadataType, void* HDRMetadata, void* PresentParameters, int PlaneCount) {

	if (!InitFrame(reinterpret_cast<IDXGISwapChain*>(SwapChain))) {

		RestoreAddress(fPresentMultiplaneOverlayAddress, fPresentMultiplaneOverlayBackupBytes, fPresentMultiplaneOverlayPatchSize);

		return fPresentMultiplaneOverlayTrampoline(__this, SwapChain, SyncInterval, Flags, MetadataType, HDRMetadata, PresentParameters, PlaneCount);
	}

	SimulateMouseInputToImGui();

	DrawImGui();

	return fPresentMultiplaneOverlayTrampoline(__this, SwapChain, SyncInterval, Flags, MetadataType, HDRMetadata, PresentParameters, PlaneCount);
}
