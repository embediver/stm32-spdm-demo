#![no_std]

use core::cell::RefCell;

use embassy_stm32::i2c::{I2c, mode::MultiMaster};
use embassy_stm32::mode::Async;
use embassy_sync::blocking_mutex::ThreadModeMutex;
use embassy_time::{Delay, Instant};
use embedded_hal_async::delay::DelayNs;

use mctp::{Eid, Error, Result, Tag};
use mctp_lib::{AppCookie, Router};
use mctp_lib::{Sender, i2c::MctpI2cEncap};

use defmt::{Debug2Format, error, info};
use spdm_lib::platform::transport::{SpdmTransport, TransportError, TransportResult};

const MTU: usize = 255;

pub const LISTEN_HANDLES: usize = 8;
pub const REQ_HANDLES: usize = 8;

pub struct I2cSender<'a> {
    pub i2c: &'a ThreadModeMutex<RefCell<I2c<'static, Async, MultiMaster>>>,
    pub remote_addr: u8,
    pub own_addr: u8,
}

impl Sender for I2cSender<'_> {
    fn send_vectored(
        &mut self,
        _eid: Eid,
        mut fragmenter: mctp_lib::fragment::Fragmenter,
        payload: &[&[u8]],
    ) -> Result<Tag> {
        let encap = MctpI2cEncap::new(self.own_addr);

        info!(
            "Sending MTCP message: src_addr {:02x}, dest_addr {:02x}",
            self.own_addr, self.remote_addr
        );

        loop {
            let mut pkt = [0; MTU - 8];

            let r = fragmenter.fragment_vectored(payload, &mut pkt);

            match r {
                mctp_lib::fragment::SendOutput::Packet(items) => {
                    info!("Sending {} bytes of data + heder + pec...", items.len());
                    let mut out = [0; MTU];
                    let pkt = encap.encode(self.remote_addr, items, &mut out, true)?;
                    self.i2c.lock(|i2c| {
                        let mut i2c = i2c.borrow_mut();
                        i2c.blocking_write(self.remote_addr, pkt).map_err(|e| {
                            error!("I2C send error: {}", e);
                            Error::TxFailure
                        })
                    })?;
                }
                mctp_lib::fragment::SendOutput::Complete { tag, cookie: _ } => {
                    info!("Finished sending MCTP message");
                    return Ok(tag);
                }
                mctp_lib::fragment::SendOutput::Error { err, cookie: _ } => {
                    error!(
                        "Fragmenter error while sending message: {}",
                        Debug2Format(&err)
                    );
                    return Err(err);
                }
            }
        }
    }

    fn get_mtu(&self) -> usize {
        MTU
    }
}

pub async fn server_loop<'a>(
    router: &'a ThreadModeMutex<RefCell<Router<I2cSender<'a>, LISTEN_HANDLES, REQ_HANDLES>>>,
) {
    loop {
        let sleep = router.lock(|r| {
            let mut r = r.borrow_mut();
            r.update(Instant::now().as_millis()).unwrap()
        });
        Delay.delay_ms(sleep as u32).await;
    }
}

pub struct Transport<'a> {
    router: &'a ThreadModeMutex<RefCell<Router<I2cSender<'a>, LISTEN_HANDLES, REQ_HANDLES>>>,
    i2c: &'a ThreadModeMutex<RefCell<I2c<'static, Async, MultiMaster>>>,
    own_i2c_addr: u8,
    req_handle: Option<AppCookie>,
    req: Option<(Eid, Tag)>,
}

impl<'r> SpdmTransport for Transport<'r> {
    fn init_sequence(&mut self) -> spdm_lib::platform::transport::TransportResult<()> {
        Ok(())
    }

    fn send_request<'a>(
        &mut self,
        dest_eid: u8,
        req: &mut spdm_lib::codec::MessageBuf<'a>,
    ) -> spdm_lib::platform::transport::TransportResult<()> {
        self.router.lock(|r| {
            let mut r = r.borrow_mut();
            let handle = r.req(Eid(dest_eid)).unwrap();
            r.send(
                None,
                mctp::MCTP_TYPE_SPDM,
                None,
                mctp::MsgIC(false),
                handle,
                req.message_data().unwrap(),
            )
            .unwrap();
            self.req_handle = Some(handle);
        });
        Ok(())
    }

    fn receive_response<'a>(
        &mut self,
        rsp: &mut spdm_lib::codec::MessageBuf<'a>,
    ) -> spdm_lib::platform::transport::TransportResult<()> {
        let Some(handle) = self.req_handle else {
            return Err(spdm_lib::platform::transport::TransportError::ResponseNotExpected);
        };
        self.router.lock(|r| {
            let mut r = r.borrow_mut();

            // First check if a message was already received by the stack
            let mut done = false;
            if let Some(m) = r.recv(handle) {
                rsp.reset();
                rsp.put_data(m.payload.len())
                    .map_err(|_| TransportError::BufferTooSmall)?;

                rsp.data_mut(m.payload.len())
                    .map_err(|_| TransportError::BufferTooSmall)?
                    .copy_from_slice(m.payload);
                done = true;
            }
            if done {
                r.unbind(handle).unwrap();
                self.req_handle = None;
                return Ok(());
            }

            // Otherwise loop until a message that matches our handle is received
            loop {
                let mut buf = [0; MTU];
                let packet = self.i2c_receive(&mut buf)?;
                let decoder = MctpI2cEncap::new(self.own_i2c_addr);
                let (mctp_pkt, header) = decoder.decode(packet, true).map_err(|e| {
                    error!("Error decoding i2c packet: {}", Debug2Format(&e));
                    TransportError::ReceiveError
                })?;
                info!(
                    "Received mctp packet with source {:02x}, dest {:02x}",
                    header.source, header.dest
                );
                let inbound = r.inbound(mctp_pkt).map_err(|e| {
                    error!("Error processing inbound MCTP packet: {}", Debug2Format(&e));
                    TransportError::ReceiveError
                })?;
                if inbound == Some(handle) {
                    break;
                }
            }

            if let Some(m) = r.recv(handle) {
                rsp.reset();
                rsp.put_data(m.payload.len())
                    .map_err(|_| TransportError::BufferTooSmall)?;

                rsp.data_mut(m.payload.len())
                    .map_err(|_| TransportError::BufferTooSmall)?
                    .copy_from_slice(m.payload);
            }

            r.unbind(handle).unwrap();
            self.req_handle = None;
            Ok(())
        })
    }

    fn receive_request<'a>(
        &mut self,
        req: &mut spdm_lib::codec::MessageBuf<'a>,
    ) -> spdm_lib::platform::transport::TransportResult<()> {
        self.router.lock(|r| {
            let mut r = r.borrow_mut();
            let handle = r.listener(mctp::MCTP_TYPE_SPDM).unwrap();

            // First check if a message was already received by the stack
            let mut done = false;
            if let Some(m) = r.recv(handle) {
                self.req_handle = m.cookie();
                self.req = Some((m.source, m.tag));
                req.reset();
                req.put_data(m.payload.len())
                    .map_err(|_| TransportError::BufferTooSmall)?;

                req.data_mut(m.payload.len())
                    .map_err(|_| TransportError::BufferTooSmall)?
                    .copy_from_slice(m.payload);
                done = true;
            }
            if done {
                r.unbind(handle).unwrap();
                return Ok(());
            }

            // Otherwise loop until a message that matches our handle is received
            loop {
                let mut buf = [0; MTU];
                let packet = self.i2c_receive(&mut buf)?;
                let decoder = MctpI2cEncap::new(self.own_i2c_addr);
                let (mctp_pkt, header) = decoder.decode(packet, true).map_err(|e| {
                    error!("Error decoding i2c packet: {}", Debug2Format(&e));
                    TransportError::ReceiveError
                })?;
                info!(
                    "Received mctp packet with source {:02x}, dest {:02x}",
                    header.source, header.dest
                );
                let inbound = r.inbound(mctp_pkt).map_err(|e| {
                    error!("Error processing inbound MCTP packet: {}", Debug2Format(&e));
                    TransportError::ReceiveError
                })?;
                if inbound == Some(handle) {
                    break;
                }
            }

            if let Some(m) = r.recv(handle) {
                self.req_handle = m.cookie();
                self.req = Some((m.source, m.tag));
                req.reset();
                req.put_data(m.payload.len())
                    .map_err(|_| TransportError::BufferTooSmall)?;

                req.data_mut(m.payload.len())
                    .map_err(|_| TransportError::BufferTooSmall)?
                    .copy_from_slice(m.payload);
            }

            r.unbind(handle).unwrap();
            Ok(())
        })
    }

    fn send_response<'a>(
        &mut self,
        resp: &mut spdm_lib::codec::MessageBuf<'a>,
    ) -> spdm_lib::platform::transport::TransportResult<()> {
        let Some(handle) = self.req_handle else {
            return Err(spdm_lib::platform::transport::TransportError::ResponseNotExpected);
        };
        let Some((eid, tag)) = self.req else {
            return Err(spdm_lib::platform::transport::TransportError::ResponseNotExpected);
        };
        self.router.lock(|r| {
            let mut r = r.borrow_mut();
            r.send(
                Some(eid),
                mctp::MCTP_TYPE_SPDM,
                Some(tag),
                mctp::MsgIC(false),
                handle,
                resp.message_data().unwrap(),
            )
            .unwrap();
            self.req_handle = None;
            self.req = None;
        });
        Ok(())
    }

    fn max_message_size(&self) -> spdm_lib::platform::transport::TransportResult<usize> {
        Ok(mctp_lib::config::MAX_PAYLOAD)
    }

    fn header_size(&self) -> usize {
        0
    }
}

impl<'a> Transport<'a> {
    fn i2c_receive<'b>(&mut self, buf: &'b mut [u8]) -> TransportResult<&'b [u8]> {
        self.i2c.lock(|i2c| {
            let mut i2c = i2c.borrow_mut();
            let cmd = i2c.blocking_listen().map_err(|e| {
                error!("i2c listen error: {}", e);
                TransportError::ReceiveError
            })?;
            match cmd.kind {
                embassy_stm32::i2c::SlaveCommandKind::Write => {}
                embassy_stm32::i2c::SlaveCommandKind::Read => {
                    error!("i2c received (unhandled) read command");
                    return Err(TransportError::ReceiveError);
                }
            }
            let n = i2c.blocking_respond_to_write(buf).map_err(|e| {
                error!("i2c respond to write error: {}", e);
                TransportError::ReceiveError
            })?;
            Ok(&buf[..n])
        })
    }

    pub fn new(
        router: &'a ThreadModeMutex<RefCell<Router<I2cSender<'a>, LISTEN_HANDLES, REQ_HANDLES>>>,
        i2c: &'a ThreadModeMutex<RefCell<I2c<'static, Async, MultiMaster>>>,
        own_i2c_addr: u8,
    ) -> Self {
        Transport {
            router,
            i2c,
            own_i2c_addr,
            req_handle: None,
            req: None,
        }
    }
}
