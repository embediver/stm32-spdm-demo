#![no_std]
#![no_main]

use defmt::*;
use embassy_executor::Spawner;
use embassy_stm32::{
    Config, bind_interrupts, dma,
    i2c::{self, MultiMaster},
    mode::Async,
    peripherals,
    rcc::Pll,
};
use embassy_sync::blocking_mutex::ThreadModeMutex;
use embassy_time::{Duration, Instant};
use mctp::Eid;
use mctp_lib::Router;
use spdm_lib::{
    codec::MessageBuf,
    context::SpdmContext,
    protocol::{CapabilityFlags, DeviceCapabilities, SpdmVersion},
};
use {defmt_rtt as _, panic_probe as _};

use core::cell::RefCell;
use static_cell::StaticCell;

use mctp_transport::{I2cSender, LISTEN_HANDLES, REQ_HANDLES, Transport, server_loop};

use spdm_platform::*;

const OWN_I2C_ADDR: u8 = 0x2b;
const REMOTE_I2C_ADDR: u8 = 0x2a;
const OWN_EID: u8 = 10;

bind_interrupts!(struct Irqs {
    I2C2_ER => i2c::ErrorInterruptHandler<peripherals::I2C2>;
    I2C2_EV => i2c::EventInterruptHandler<peripherals::I2C2>;
    GPDMA1_CHANNEL0 => dma::InterruptHandler<peripherals::GPDMA1_CH0>;
    GPDMA1_CHANNEL1 => dma::InterruptHandler<peripherals::GPDMA1_CH1>;
    RNG => embassy_stm32::rng::InterruptHandler<peripherals::RNG>;
});
#[embassy_executor::main]
async fn main(spawner: Spawner) -> ! {
    let mut config = Config::default();
    let pll1 = Pll {
        source: embassy_stm32::rcc::PllSource::MSIS,
        prediv: embassy_stm32::rcc::PllPreDiv::DIV1, // 16 MHz / 1 = 16 MHz
        mul: embassy_stm32::rcc::PllMul::MUL10,      // 16 MHz * 10 = 160 MHz
        divp: None,
        divq: None,
        divr: Some(embassy_stm32::rcc::PllDiv::DIV1),
    };
    config.rcc = embassy_stm32::rcc::Config {
        msis: Some(embassy_stm32::rcc::MSIRange::RANGE_16MHZ),
        pll1: Some(pll1),
        sys: embassy_stm32::rcc::Sysclk::PLL1_R,
        voltage_range: embassy_stm32::rcc::VoltageScale::RANGE1,
        ..Default::default()
    };
    let p = embassy_stm32::init(config);
    info!("SPDM Responder starting...");

    // Init I2C
    let i2c_p = p.I2C2;
    let scl = p.PF1;
    let sda = p.PF0;
    let tx_dma = p.GPDMA1_CH0;
    let rx_dma = p.GPDMA1_CH1;
    let mut i2c_conf = i2c::Config::default();
    i2c_conf.timeout = Duration::from_secs(600);

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

    // Setup SPDM context
    let mut ctx = SpdmContext::new(
        &[SpdmVersion::V12],
        &mut transport,
        capabilities,
        local_algorithms,
        &mut cert_store,
        None,
        &mut spdm_hash,
        &mut m1_hash,
        &mut l1_hash,
        &mut mock_rng,
        &evidence,
    )
    .unwrap();

    info!("Setup complete, waiting for incoming connections...");

    let mut response_buf = [0u8; 4096];
    let mut msg_buf = MessageBuf::new(&mut response_buf);
    loop {
        msg_buf.reset();
        match ctx.responder_process_message(&mut msg_buf) {
            Ok(_) => {
                info!("Processed SPDM request successfully");
            }
            Err(e) => {
                error!("Error processing SPDM request {:?}", Debug2Format(&e));
                // Continue processing — don't exit on individual message errors
            }
        }
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
