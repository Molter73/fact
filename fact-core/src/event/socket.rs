use std::net::IpAddr;

use byteorder::{ByteOrder, NetworkEndian};
use fact_ebpf::event_t__bindgen_ty_1__bindgen_ty_2;
use libc::AF_INET;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum SocketData {
    Listen(ListenData),
}

impl From<SocketData> for fact_api::network_activity::Net {
    fn from(value: SocketData) -> Self {
        match value {
            SocketData::Listen(ListenData { addr, port }) => {
                let sock = fact_api::Socket {
                    address: addr.to_string(),
                    port: port as u32,
                };
                fact_api::network_activity::Net::Listen(sock)
            }
        }
    }
}

impl From<fact_api::network_activity::Net> for SocketData {
    fn from(value: fact_api::network_activity::Net) -> Self {
        match value {
            fact_api::network_activity::Net::Listen(fact_api::Socket { address, port }) => {
                let data = ListenData {
                    addr: address.parse().expect("Invalid IP address"),
                    port: port as u16,
                };
                SocketData::Listen(data)
            }
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct ListenData {
    addr: IpAddr,
    port: u16,
}

impl ListenData {
    pub(super) fn new(data: event_t__bindgen_ty_1__bindgen_ty_2) -> Self {
        let addr = if data.family == AF_INET as u16 {
            let addr = NetworkEndian::read_u32(&data.address);
            IpAddr::V4(addr.into())
        } else {
            let addr = NetworkEndian::read_u128(&data.address);
            IpAddr::V6(addr.into())
        };
        let port = data.port;

        ListenData { addr, port }
    }
}
