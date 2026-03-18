#[macro_export]
macro_rules! impl_empty_default {
    ([u8][$sz:expr]) => {
        [0u8; $sz]
    };
    (u32) => {
        0u32
    };
    (u64) => {
        0u64
    };
    (bool) => {
        false
    };
    ({$ty:ty}) => {
        <$ty>::empty()
    };
    ((option [u8][$sz:expr])) => {
        Some([0u8; $sz])
    };
    ((option {$ty:ty})) => {
        Some(<$ty>::empty())
    };
}

#[macro_export]
macro_rules! impl_empty_size {
    ([u8][$sz:expr]) => {
        $sz
    };
    (u32) => {
        4
    };
    (u64) => {
        8
    };
    (bool) => {
        1
    };
    ({$ty:ty}) => {
        <$ty>::byte_sz()
    };
    ((option [u8][$sz:expr])) => {
        1 + $sz
    };
    ((option {$ty:ty})) => {
        1 + <$ty>::byte_sz()
    };
}

#[macro_export]
macro_rules! impl_empty_obj {
    ( $struct:ident; $( $field:ident : $ty:tt $( [$sz:expr] )? ),* $(,)? ) => {
        fn empty() -> Self {
            Self {
                $( $field: impl_empty_default!($ty $( [$sz] )? ), )*
            }
        }
        fn byte_sz() -> usize {
            0 $( + impl_empty_size!($ty $( [$sz] )? ) )*
        }
    };
}

#[macro_export]
macro_rules! impl_empty_to_bytes {
    ( $struct:ident; $( $field:ident : $ty:tt $( [$sz:expr] )? ),* $(,)? ) => {
        fn to_bytes(&self) -> Vec<u8> {
            let mut v = Vec::with_capacity(Self::byte_sz());
            $( impl_empty_to_bytes!(@push v, self.$field, $ty $( [$sz] )? ); )*
            v
        }
    };
    (@push $v:ident, $f:expr, [u8][$_sz:expr]) => { $v.extend_from_slice(&$f);               };
    (@push $v:ident, $f:expr, u32)             => { $v.extend_from_slice(&$f.to_le_bytes());  };
    (@push $v:ident, $f:expr, u64)             => { $v.extend_from_slice(&$f.to_le_bytes());  };
    (@push $v:ident, $f:expr, bool)            => { $v.push($f as u8);                        };
    (@push $v:ident, $f:expr, {$_ty:ty})       => { $v.extend_from_slice(&$f.to_bytes());     };
    (@push $v:ident, $f:expr, (option [u8][$sz:expr])) => {
        match $f {
            Some(arr) => { $v.push(1u8); $v.extend_from_slice(&arr);        }
            None      => { $v.push(0u8); $v.extend_from_slice(&[0u8; $sz]); }
        }
    };
    (@push $v:ident, $f:expr, (option {$ty:ty})) => {
        match $f {
            Some(inner) => { $v.push(1u8); $v.extend_from_slice(&inner.to_bytes());          }
            None        => { $v.push(0u8); $v.extend_from_slice(&<$ty>::empty().to_bytes()); }
        }
    };
}

#[macro_export]
macro_rules! impl_empty_from_bytes {
    ( $struct:ident; $( $field:ident : $ty:tt $( [$sz:expr] )? ),* $(,)? ) => {
        fn from_bytes(b: Vec<u8>) -> Self {
            let mut off = 0usize;
            $( let $field = impl_empty_from_bytes!(@pull b, off, $ty $( [$sz] )? ); )*
            Self { $( $field ),* }
        }
    };
    (@pull $b:ident, $off:ident, [u8][$sz:expr]) => {{
        let mut arr = [0u8; $sz];
        arr.copy_from_slice(&$b[$off..$off + $sz]);
        $off += $sz;
        arr
    }};
    (@pull $b:ident, $off:ident, u32) => {{
        let arr: [u8; 4] = $b[$off..$off + 4].try_into().unwrap();
        $off += 4;
        u32::from_le_bytes(arr)
    }};
    (@pull $b:ident, $off:ident, u64) => {{
        let arr: [u8; 8] = $b[$off..$off + 8].try_into().unwrap();
        $off += 8;
        u64::from_le_bytes(arr)
    }};
    (@pull $b:ident, $off:ident, bool) => {{
        let val = $b[$off] != 0;
        $off += 1;
        val
    }};
    (@pull $b:ident, $off:ident, {$ty:ty}) => {{
        let sz = <$ty>::byte_sz();
        let val = <$ty>::from_bytes($b[$off..$off + sz].to_vec());
        $off += sz;
        val
    }};
    (@pull $b:ident, $off:ident, (option [u8][$sz:expr])) => {{
        let present = $b[$off] != 0;
        $off += 1;
        let mut arr = [0u8; $sz];
        arr.copy_from_slice(&$b[$off..$off + $sz]);
        $off += $sz;
        if present { Some(arr) } else { None }
    }};
    (@pull $b:ident, $off:ident, (option {$ty:ty})) => {{
        let present = $b[$off] != 0;
        $off += 1;
        let sz = <$ty>::byte_sz();
        let val = <$ty>::from_bytes($b[$off..$off + sz].to_vec());
        $off += sz;
        if present { Some(val) } else { None }
    }};
}
