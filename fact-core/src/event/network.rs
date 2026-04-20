use std::net::IpAddr;

use byteorder::{ByteOrder, NetworkEndian};
use fact_ebpf::{event_t__bindgen_ty_1__bindgen_ty_2__bindgen_ty_1__bindgen_ty_1, fact_socket_t};
use libc::AF_INET;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum NetworkData {
    Accept(SocketTuple),
    Connect(SocketTuple),
    Listen(SocketData),
}

impl From<NetworkData> for fact_api::network_activity::Net {
    fn from(value: NetworkData) -> Self {
        match value {
            NetworkData::Listen(sock) => fact_api::network_activity::Net::Listen(sock.into()),
            NetworkData::Accept(tuple) => fact_api::network_activity::Net::Accept(tuple.into()),
            NetworkData::Connect(tuple) => fact_api::network_activity::Net::Connect(tuple.into()),
        }
    }
}

impl From<fact_api::network_activity::Net> for NetworkData {
    fn from(value: fact_api::network_activity::Net) -> Self {
        match value {
            fact_api::network_activity::Net::Listen(sock) => NetworkData::Listen(sock.into()),
            fact_api::network_activity::Net::Accept(tuple) => NetworkData::Accept(tuple.into()),
            fact_api::network_activity::Net::Connect(tuple) => NetworkData::Connect(tuple.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SocketData {
    addr: IpAddr,
    port: u16,
}

impl SocketData {
    pub(super) fn new(data: fact_socket_t, family: u16) -> Self {
        let addr = if family == AF_INET as u16 {
            let addr = NetworkEndian::read_u32(&data.address);
            IpAddr::V4(addr.into())
        } else {
            let addr = NetworkEndian::read_u128(&data.address);
            IpAddr::V6(addr.into())
        };
        let port = data.port;

        Self { addr, port }
    }
}

impl From<SocketData> for fact_api::Socket {
    fn from(SocketData { addr, port }: SocketData) -> Self {
        fact_api::Socket {
            address: addr.to_string(),
            port: port as u32,
        }
    }
}

impl From<fact_api::Socket> for SocketData {
    fn from(fact_api::Socket { address, port }: fact_api::Socket) -> Self {
        SocketData {
            addr: address.parse().expect("Invalid IP address"),
            port: port as u16,
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SocketTuple {
    local: SocketData,
    remote: SocketData,
}

impl SocketTuple {
    pub(super) fn new(
        data: event_t__bindgen_ty_1__bindgen_ty_2__bindgen_ty_1__bindgen_ty_1,
        family: u16,
    ) -> Self {
        let local = SocketData::new(data.local, family);
        let remote = SocketData::new(data.remote, family);

        SocketTuple { local, remote }
    }
}

impl From<SocketTuple> for fact_api::SocketTuple {
    fn from(SocketTuple { local, remote }: SocketTuple) -> Self {
        fact_api::SocketTuple {
            local: Some(local.into()),
            remote: Some(remote.into()),
        }
    }
}

impl From<fact_api::SocketTuple> for SocketTuple {
    fn from(value: fact_api::SocketTuple) -> Self {
        let fact_api::SocketTuple {
            local: Some(local),
            remote: Some(remote),
        } = value
        else {
            unreachable!("Invalid accept message");
        };

        SocketTuple {
            local: local.into(),
            remote: remote.into(),
        }
    }
}
