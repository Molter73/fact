use std::net::IpAddr;

use byteorder::{ByteOrder, NetworkEndian};
use fact_ebpf::{event_t__bindgen_ty_1__bindgen_ty_2, fact_socket_t};
use libc::AF_INET;
use serde::Serialize;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum NetworkData {
    Accept(AcceptData),
    Listen(ListenData),
}

impl From<NetworkData> for fact_api::network_activity::Net {
    fn from(value: NetworkData) -> Self {
        match value {
            NetworkData::Listen(ListenData(sock)) => {
                fact_api::network_activity::Net::Listen(sock.into())
            }
            NetworkData::Accept(data) => fact_api::network_activity::Net::Accept(data.into()),
        }
    }
}

impl From<fact_api::network_activity::Net> for NetworkData {
    fn from(value: fact_api::network_activity::Net) -> Self {
        match value {
            fact_api::network_activity::Net::Listen(sock) => {
                NetworkData::Listen(ListenData(sock.into()))
            }
            fact_api::network_activity::Net::Accept(data) => NetworkData::Accept(data.into()),
        }
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct SocketData {
    addr: IpAddr,
    port: u16,
}

impl SocketData {
    fn new(data: fact_socket_t, family: u16) -> Self {
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
pub struct ListenData(SocketData);

impl ListenData {
    pub(super) fn new(data: event_t__bindgen_ty_1__bindgen_ty_2) -> Self {
        let sock = SocketData::new(unsafe { data.__bindgen_anon_1.listen }, data.family);
        ListenData(sock)
    }
}

#[derive(Debug, Clone, Serialize, PartialEq)]
pub struct AcceptData {
    local: SocketData,
    remote: SocketData,
}

impl AcceptData {
    pub(super) fn new(data: event_t__bindgen_ty_1__bindgen_ty_2) -> Self {
        let local = SocketData::new(unsafe { data.__bindgen_anon_1.accept.local }, data.family);
        let remote = SocketData::new(unsafe { data.__bindgen_anon_1.accept.remote }, data.family);

        AcceptData { local, remote }
    }
}

impl From<AcceptData> for fact_api::Accept {
    fn from(AcceptData { local, remote }: AcceptData) -> Self {
        fact_api::Accept {
            local: Some(local.into()),
            remote: Some(remote.into()),
        }
    }
}

impl From<fact_api::Accept> for AcceptData {
    fn from(value: fact_api::Accept) -> Self {
        let fact_api::Accept {
            local: Some(local),
            remote: Some(remote),
        } = value
        else {
            unreachable!("Invalid accept message");
        };

        AcceptData {
            local: local.into(),
            remote: remote.into(),
        }
    }
}
