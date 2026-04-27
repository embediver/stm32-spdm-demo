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
use embassy_time::Instant;
use mctp::Eid;
use mctp_lib::Router;
use {defmt_rtt as _, panic_probe as _};

use core::cell::RefCell;
use static_cell::StaticCell;

use mctp_transport::{I2cSender, LISTEN_HANDLES, REQ_HANDLES, Transport, server_loop};

const OWN_I2C_ADDR: u8 = 0x42;
const REMOTE_I2C_ADDR: u8 = 0x9e;
const OWN_EID: u8 = 10;

bind_interrupts!(struct I2cIrqs {
    I2C1_ER => i2c::ErrorInterruptHandler<peripherals::I2C1>;
    I2C1_EV => i2c::EventInterruptHandler<peripherals::I2C1>;
    GPDMA1_CHANNEL0 => dma::InterruptHandler<peripherals::GPDMA1_CH0>;
    GPDMA1_CHANNEL1 => dma::InterruptHandler<peripherals::GPDMA1_CH1>;
});
#[embassy_executor::main]
async fn main(spawner: Spawner) -> ! {
    let p = embassy_stm32::init(Default::default());
    info!("SPDM Responder starting...");

    // Init I2C
    let i2c_p = p.I2C1;
    let scl = p.PB6;
    let sda = p.PB3;
    let tx_dma = p.GPDMA1_CH0;
    let rx_dma = p.GPDMA1_CH1;
    let i2c_conf = i2c::Config::default();

    let i2c = i2c::I2c::new(i2c_p, scl, sda, tx_dma, rx_dma, I2cIrqs, i2c_conf);

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

    // Setup SPDM Transport
    let _transport = Transport::new(router, i2c_mutex, OWN_I2C_ADDR);

    loop {
        embassy_time::Timer::after_millis(1000).await;
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
