#![no_std]
#![no_main]

use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext,
};
use aya_log_ebpf::info;

#[tracepoint(name = "aya_tracepoint")]
pub fn aya_tracepoint(ctx: TracePointContext) -> u32 {
    match try_aya_tracepoint(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_aya_tracepoint(ctx: TracePointContext) -> Result<u32, u32> {
    info!(&ctx, "tracepoint sys_enter_sendto called");
    Ok(0)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
