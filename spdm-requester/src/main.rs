#![no_std]
#![no_main]

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::{
    bind_interrupts, dma,
    i2c::{self, MultiMaster},
    mode::Async,
    peripherals,
};
use embassy_sync::blocking_mutex::ThreadModeMutex;
use embassy_time::{Duration, Instant};
use mctp::Eid;
use mctp_lib::Router;
use spdm_lib::commands::certificate::request::generate_get_certificate;
use spdm_lib::commands::digests::request::generate_digest_request;
use spdm_lib::commands::version::VersionReqPayload;
use spdm_lib::commands::version::request::generate_get_version;
use spdm_lib::commands::{
    algorithms::request::generate_negotiate_algorithms_request,
    challenge::MeasurementSummaryHashType,
};
use spdm_lib::commands::{
    capabilities::request::generate_capabilities_request_local,
    challenge::request::generate_challenge_request,
};
// TODO use spdm_lib::protocol::signature::NONCE_LEN;
use spdm_lib::{
    codec::MessageBuf,
    context::SpdmContext,
    protocol::{CapabilityFlags, DeviceCapabilities, SpdmVersion, signature::NONCE_LEN},
};
use {defmt_rtt as _, panic_probe as _};

use core::cell::RefCell;
use static_cell::StaticCell;

use mctp_transport::{I2cSender, LISTEN_HANDLES, REQ_HANDLES, Transport, server_loop};

use spdm_platform::*;

const OWN_I2C_ADDR: u8 = 0x2a;
const REMOTE_I2C_ADDR: u8 = 0x2b;
const OWN_EID: u8 = 11;
const RESPONDER_EID: u8 = 10;

bind_interrupts!(struct Irqs {
    I2C2_ER => i2c::ErrorInterruptHandler<peripherals::I2C2>;
    I2C2_EV => i2c::EventInterruptHandler<peripherals::I2C2>;
    DMA1_STREAM0 => dma::InterruptHandler<peripherals::DMA1_CH0>;
    DMA1_STREAM1 => dma::InterruptHandler<peripherals::DMA1_CH1>;
    HASH_RNG => embassy_stm32::rng::InterruptHandler<peripherals::RNG>;
});

#[embassy_executor::main]
async fn main(spawner: Spawner) -> ! {
    let p = embassy_stm32::init(Default::default());
    info!("SPDM Requester starting...");

    // Init I2C
    let i2c_p = p.I2C2;
    let scl = p.PF1;
    let sda = p.PF0;
    let tx_dma = p.DMA1_CH0;
    let rx_dma = p.DMA1_CH1;
    let mut i2c_conf = i2c::Config::default();
    i2c_conf.timeout = Duration::from_secs(2);
    i2c_conf.scl_pullup = true;
    i2c_conf.sda_pullup = true;

    let i2c = i2c::I2c::new(i2c_p, scl, sda, tx_dma, rx_dma, Irqs, i2c_conf);

    let i2c = i2c.into_slave_multimaster(i2c::SlaveAddrConfig::basic(OWN_I2C_ADDR));
    let i2c = ThreadModeMutex::new(RefCell::new(i2c));
    static I2C: StaticCell<ThreadModeMutex<RefCell<i2c::I2c<'static, Async, MultiMaster>>>> =
        StaticCell::new();
    let i2c_mutex = I2C.init(i2c);

    // Init MCTP Router
    let sender = I2cSender {
        i2c: i2c_mutex,
        remote_addr: REMOTE_I2C_ADDR,
        own_addr: OWN_I2C_ADDR,
    };

    let mut router: Router<I2cSender<'static>, LISTEN_HANDLES, REQ_HANDLES> =
        Router::new(mctp::Eid(OWN_EID), Instant::now().as_millis(), sender);

    router.set_eid(Eid(OWN_EID)).unwrap();

    let router = ThreadModeMutex::new(RefCell::new(router));
    static ROUTER: StaticCell<
        ThreadModeMutex<RefCell<Router<I2cSender<'static>, LISTEN_HANDLES, REQ_HANDLES>>>,
    > = StaticCell::new();
    let router = ROUTER.init(router);
    spawner.spawn(mctp_loop(router).unwrap());
    embassy_time::Timer::after_millis(100).await;

    // Setup SPDM platform
    let mut transport = Transport::new(router, i2c_mutex, OWN_I2C_ADDR);
    let mut cert_store = DemoCertStore;
    let local_algorithms = create_local_algorithms();
    let mut spdm_hash = MockHash::default();
    let mut m1_hash = MockHash::default();
    let mut l1_hash = MockHash::default();
    let rng = embassy_stm32::rng::Rng::new(p.RNG, Irqs);
    let mut mock_rng = PlatformRng::new(rng);
    let evidence = MockEvidence;
    let capabilities = create_spdm_caps();
    let mut peer_cert_store = DemoPeerCertStore::default();

    info!("Setup complete, starting SPDM flow...");

    // Setup SPDM context
    let mut ctx = SpdmContext::new(
        &[SpdmVersion::V12],
        &mut transport,
        capabilities,
        local_algorithms,
        &mut cert_store,
        Some(&mut peer_cert_store),
        &mut spdm_hash,
        &mut m1_hash,
        &mut l1_hash,
        &mut mock_rng,
        &evidence,
    )
    .unwrap();

    let mut response_buf = [0u8; 4096];
    let mut msg_buf = MessageBuf::new(&mut response_buf);
    msg_buf.reset();
    info!("Step 1: GET_VERSION");
    {
        generate_get_version(&mut ctx, &mut msg_buf, VersionReqPayload::new(0, 0))
            .map_err(|_| "Failed to generate GET_VERSION request")
            .unwrap();
        ctx.requester_send_request(&mut msg_buf, RESPONDER_EID)
            .map_err(|_| "Failed to send GET_VERSION request")
            .unwrap();
    }
    {
        msg_buf.reset();
        ctx.requester_process_message(&mut msg_buf)
            .map_err(|_| "Failed to process VERSION response")
            .unwrap();
    }
    info!("  GET_VERSION completed successfully");

    info!("Step 2: GET_CAPABILITIES");
    {
        msg_buf.reset();
        generate_capabilities_request_local(&mut ctx, &mut msg_buf)
            .map_err(|_| "Failed to generate GET_CAPABILITIES request")
            .unwrap();
        ctx.requester_send_request(&mut msg_buf, RESPONDER_EID)
            .map_err(|_| "Failed to send GET_CAPABILITIES request")
            .unwrap();
    }
    {
        msg_buf.reset();
        ctx.requester_process_message(&mut msg_buf)
            .map_err(|_| "Failed to process CAPABILITIES response")
            .unwrap();
    }
    info!("  GET_CAPABILITIES completed successfully");

    info!("Step 3: NEGOTIATE_ALGORITHMS");
    {
        msg_buf.reset();
        generate_negotiate_algorithms_request(&mut ctx, &mut msg_buf, None, None, None, None)
            .map_err(|_| "Failed to generate NEGOTIATE_ALGORITHMS request")
            .unwrap();
        ctx.requester_send_request(&mut msg_buf, RESPONDER_EID)
            .map_err(|_| "Failed to send NEGOTIATE_ALGORITHMS request")
            .unwrap();
    }
    {
        msg_buf.reset();
        ctx.requester_process_message(&mut msg_buf)
            .map_err(|_| "Failed to process ALGORITHMS response")
            .unwrap();
    }
    info!("  NEGOTIATE_ALGORITHMS completed successfully");

    println!("\n  VCA (Version, Capabilities, Algorithms) flow completed!\n");

    info!("Step 4: GET_DIGESTS");
    {
        msg_buf.reset();
        generate_digest_request(&mut ctx, &mut msg_buf)
            .map_err(|_| "Failed to generate GET_DIGESTS request")
            .unwrap();
        ctx.requester_send_request(&mut msg_buf, RESPONDER_EID)
            .map_err(|_| "Failed to send GET_DIGESTS request")
            .unwrap();
    }
    {
        msg_buf.reset();
        ctx.requester_process_message(&mut msg_buf)
            .map_err(|e| {
                error!("{}", Debug2Format(&e));
                "Failed to process DIGESTS response"
            })
            .unwrap();
    }
    info!("  GET_DIGESTS completed successfully");
    let cert_store = ctx.peer_cert_store().unwrap();
    let provisioned_slots = cert_store.get_provisioned_slots().unwrap();
    info!("  Provisioned slots: {:08b}", provisioned_slots);
    for slot in 0..8 {
        if (provisioned_slots & 1 << slot) > 0 {
            info!(
                "  Slot {} digest: {:02x}",
                slot,
                cert_store.get_digest(slot).unwrap()
            );
        }
    }

    info!("Step 5: GET_CERTIFICATE");
    loop {
        msg_buf.reset();
        generate_get_certificate(&mut ctx, &mut msg_buf, 0, 0, 0x200, false).unwrap();
        ctx.requester_send_request(&mut msg_buf, RESPONDER_EID)
            .unwrap();

        ctx.requester_process_message(&mut msg_buf).unwrap();
        if !matches!(
            ctx.connection_info().state(),
            spdm_lib::state::ConnectionState::DuringCertificate(_)
        ) {
            break;
        }
    }
    println!("\n  sucessfully retrieved peer cert chain\n");
    let cert_store = ctx.peer_cert_store().unwrap();
    let provisioned_slots = cert_store.get_provisioned_slots().unwrap();
    let hash_algo = ctx.connection_info().peer_algorithms().base_hash_algo;
    for slot in 0..8 {
        if (provisioned_slots & 1 << slot) > 0 {
            println!(
                "  Slot {} root cert hash: {:02x}",
                slot,
                cert_store
                    .get_root_hash(slot, hash_algo.try_into().unwrap())
                    .unwrap()
            );
        }
    }

    info!("Step 6: CHALLENGE");
    let mut nonce = [0u8; NONCE_LEN];
    ctx.get_random_bytes(&mut nonce).unwrap();
    trace!("  Nonce: {:02x}", nonce);

    {
        msg_buf.reset();
        generate_challenge_request(
            &mut ctx,
            &mut msg_buf,
            0,
            MeasurementSummaryHashType::All,
            nonce,
            None,
        )
        .unwrap();

        ctx.requester_send_request(&mut msg_buf, RESPONDER_EID)
            .unwrap();
        msg_buf.reset();
        ctx.requester_process_message(&mut msg_buf).unwrap();
    }
    info!("  Got CHALLENGE_AUTH from responder");

    // cortex_m::peripheral::SCB::sys_reset()
    loop {
        embassy_time::Timer::after_millis(120000).await;
    }
}

#[embassy_executor::task]
async fn mctp_loop(
    router: &'static ThreadModeMutex<
        RefCell<Router<I2cSender<'static>, LISTEN_HANDLES, REQ_HANDLES>>,
    >,
) {
    info!("Spawned Router update loop");
    server_loop(router).await;
}

fn create_spdm_caps() -> DeviceCapabilities {
    let mut flags = CapabilityFlags::default();
    flags.set_cert_cap(1); // Certificate capability
    flags.set_chal_cap(1); // Challenge capability
    flags.set_meas_cap(2); // Measurements with signature
    flags.set_meas_fresh_cap(1); // Measurements freshness
    flags.set_chunk_cap(1); // Chunk capability
    DeviceCapabilities {
        ct_exponent: 0,
        flags,
        data_transfer_size: 1024,
        max_spdm_msg_size: 4096,
        include_supported_algorithms: true,
    }
}
