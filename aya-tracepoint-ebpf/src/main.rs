#![no_std]
#![no_main]

#[allow(non_upper_case_globals)]
#[allow(non_snake_case)]
#[allow(non_camel_case_types)]
#[allow(dead_code)]
mod vmlinux;

use vmlinux::{sockaddr, sockaddr_in, in_addr};
use core::ffi::c_void;

use aya_bpf::BpfContext;
use aya_bpf::{
    macros::tracepoint,
    programs::TracePointContext, helpers::bpf_probe_read_kernel,
};
use aya_log_ebpf::info;

const AF_INET: u16 = 2;
const AF_INET6: u16 = 10;

#[tracepoint(name = "aya_tracepoint")]
pub fn aya_tracepoint(ctx: TracePointContext) -> u32 {
    match try_aya_tracepoint(ctx) {
        Ok(ret) => ret,
        Err(ret) => match ret.try_into() {
            Ok(rt) => rt,
            Err(_) => 1,
        },
    }
}

fn try_aya_tracepoint(ctx: TracePointContext) -> Result<u32, i64> {
    info!(&ctx, "tracepoint sys_enter_sendto called");
    let sock = unsafe {
        bpf_probe_read_kernel(ctx.as_ptr() as *mut sockaddr_in)
    };
    let in_addr = unsafe {
        &(*sock).sin_addr
    };
    let addr = u32::from_be(in_addr.s_addr);
    info!(&ctx, "{}", addr);

    Ok(0)

    let addr = Ipv4Addr::from(sin_addr.s_addr);
    let sk_common = unsafe {
        bpf_probe_read_kernel(&(*sock).__sk_common as *const sock_common)
            .map_err(|e| e)?
    };

    match sk_common.skc_family {
       AF_INET => {
           let src_addr = u32::from_be(unsafe {
               sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_rcv_saddr
           });
           let dest_addr: u32 = u32::from_be(unsafe{
               sk_common.__bindgen_anon_1.__bindgen_anon_1.skc_daddr
           });
           info!(
               &ctx,
               "AF_INET: {:ipv4} -> {:ipv4}",
               src_addr,
               dest_addr,
           );
           Ok(0);
       }
        AF_INET6 => {
            let src_addr = sk_common.skc_v6_rcv_saddr;
            let dest_addr = sk_common.skc_v6_daddr;
            info!(
                &ctx,
                "AF_INET6: {:ipv6} -> {:ipv6}",
                unsafe{ src_addr.in6_u.u6_addr8 },
                unsafe{ dest_addr.in6_u.u6_addr8 }
            );
            Ok(0);
        }
        _ => Ok(0),
    }
    Ok(0)

}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}
