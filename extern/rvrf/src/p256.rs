use p256::Scalar;
use p256::{AffinePoint, FieldBytes};
#[cfg(feature = "std-rand")]
//use rand_core::OsRng;
use rand::rngs::OsRng;

use crate::traits::{Hash, PointTrait, ScalarTrait, HASH};
use core::ops::{Add, AddAssign, Mul, MulAssign, Neg, Sub, SubAssign};
use p256::elliptic_curve::sec1::{EncodedPoint, FromEncodedPoint, ToEncodedPoint};
use p256::elliptic_curve::Field;
use p256::ProjectivePoint;

use alloc::vec::Vec;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ScalarType {
    pub data: Scalar,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PointType {
    pub data: AffinePoint,
}

impl MulAssign<ScalarType> for ScalarType {
    fn mul_assign(&mut self, rhs: ScalarType) {
        *self = ScalarType {
            data: self.data * rhs.data,
        };
    }
}

impl AddAssign<ScalarType> for ScalarType {
    fn add_assign(&mut self, rhs: ScalarType) {
        *self = ScalarType {
            data: self.data + rhs.data,
        };
    }
}

impl Mul<ScalarType> for ScalarType {
    type Output = ScalarType;
    fn mul(self, other: ScalarType) -> ScalarType {
        ScalarType {
            data: self.data * other.data,
        }
    }
}

impl<'o> Mul<&'o ScalarType> for ScalarType {
    type Output = ScalarType;
    fn mul(self, other: &'o ScalarType) -> ScalarType {
        ScalarType {
            data: self.data * other.data,
        }
    }
}

impl Add<ScalarType> for ScalarType {
    type Output = ScalarType;
    fn add(self, other: ScalarType) -> ScalarType {
        ScalarType {
            data: self.data + other.data,
        }
    }
}

impl Sub<ScalarType> for ScalarType {
    type Output = ScalarType;
    fn sub(self, other: ScalarType) -> ScalarType {
        ScalarType {
            data: self.data - other.data,
        }
    }
}

impl<'o> Sub<&'o ScalarType> for ScalarType {
    type Output = ScalarType;
    fn sub(self, other: &'o ScalarType) -> ScalarType {
        ScalarType {
            data: self.data - other.data,
        }
    }
}

impl Neg for ScalarType {
    type Output = ScalarType;
    fn neg(self) -> ScalarType {
        ScalarType {
            data: Scalar::zero() - self.data,
        }
    }
}

impl ScalarTrait for ScalarType {
    type ScalarType = Scalar;

    #[cfg(feature = "std-prove")]
    fn random_scalar() -> Self {
        let mut csprng = OsRng;
        ScalarType {
            data: Scalar::random(&mut csprng),
        }
    }

    #[cfg(feature = "sgx-prove")]
    fn random_scalar() -> Self {
        use rand_sgx::OsRng;
        let mut csprng = OsRng;
        ScalarType {
            data: Scalar::random(&mut csprng),
        }
    }

    fn hash_to_scalar<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self {
        let mut array = [0; 32];
        array.clone_from_slice(&HASH.hash(input));
        let mut bytes = FieldBytes::default();
        bytes.copy_from_slice(&array);
        ScalarType {
            data: Scalar::from_bytes_reduced(&bytes),
        }
    }

    fn get_self(&self) -> Self {
        *self
    }

    fn one() -> Self {
        ScalarType {
            data: Scalar::one(),
        }
    }

    fn zero() -> Self {
        ScalarType {
            data: Scalar::zero(),
        }
    }

    fn from_u64(n: u64) -> Self {
        ScalarType {
            data: Scalar::from(n),
        }
    }

    fn bytes(&self) -> Vec<u8> {
        self.data.to_bytes().as_slice().to_vec()
    }
}

// ============

impl Mul<ScalarType> for PointType {
    type Output = PointType;

    fn mul(self, scalar: ScalarType) -> PointType {
        let point = ProjectivePoint::from(self.data);
        let scalar = scalar.data;
        PointType {
            data: (point * scalar).to_affine(),
        }
    }
}

impl Mul<&ScalarType> for PointType {
    type Output = PointType;

    fn mul(self, scalar: &ScalarType) -> PointType {
        let point = ProjectivePoint::from(self.data);
        let scalar = scalar.data;
        PointType {
            data: (point * scalar).to_affine(),
        }
    }
}

impl Mul<PointType> for ScalarType {
    type Output = PointType;

    fn mul(self, point: PointType) -> PointType {
        let point = ProjectivePoint::from(point.data);
        let scalar = self.data;
        PointType {
            data: (point * scalar).to_affine(),
        }
    }
}

impl Mul<&PointType> for ScalarType {
    type Output = PointType;

    fn mul(self, point: &PointType) -> PointType {
        let point = ProjectivePoint::from(point.data);
        let scalar = self.data;
        PointType {
            data: (point * scalar).to_affine(),
        }
    }
}

// ==============

impl AddAssign<PointType> for PointType {
    fn add_assign(&mut self, rhs: PointType) {
        *self = PointType {
            data: (ProjectivePoint::from(self.data) + rhs.data).to_affine(),
        };
    }
}

impl Add<PointType> for PointType {
    type Output = PointType;
    fn add(self, other: PointType) -> PointType {
        PointType {
            data: (ProjectivePoint::from(self.data) + other.data).to_affine(),
        }
    }
}

impl Sub<PointType> for PointType {
    type Output = PointType;
    fn sub(self, other: PointType) -> PointType {
        PointType {
            data: (ProjectivePoint::from(self.data) - other.data).to_affine(),
        }
    }
}

impl<'o> Sub<&'o PointType> for PointType {
    type Output = PointType;
    fn sub(self, other: &'o PointType) -> PointType {
        PointType {
            data: (ProjectivePoint::from(self.data) - other.data).to_affine(),
        }
    }
}

impl SubAssign for PointType {
    fn sub_assign(&mut self, other: PointType) {
        *self = PointType {
            data: (ProjectivePoint::from(self.data) - other.data).to_affine(),
        };
    }
}

impl PointTrait for PointType {
    fn hash_to_point<T: ?Sized + AsRef<[u8]>>(input: &T) -> Self {
        let mut array = [0; 32];
        array.clone_from_slice(&HASH.hash(input));
        let mut bytes = FieldBytes::default();
        bytes.copy_from_slice(array.as_ref());
        let scalar = Scalar::from_bytes_reduced(&bytes);
        PointType {
            data: (ProjectivePoint::from(AffinePoint::generator()) * scalar).to_affine(),
        }
    }

    fn generator() -> PointType {
        PointType {
            data: AffinePoint::generator(),
        }
    }

    fn generator_2() -> Self {
        PointType { data: *BASE_POINT2 }
    }

    fn point_to_bytes(&self) -> Vec<u8> {
        self.data.to_encoded_point(true).as_ref().to_vec()
    }
}

// ======================

const BASE_POINT2_X: [u8; 32] = [
    0x70, 0xf7, 0x2b, 0xba, 0xc4, 0x0e, 0x8a, 0x59, 0x4c, 0x91, 0xa7, 0xba, 0xc3, 0x76, 0x59, 0x27,
    0x89, 0x10, 0x76, 0x4c, 0xd7, 0xc2, 0x0a, 0x7d, 0x65, 0xa5, 0x9a, 0x04, 0xb0, 0xac, 0x2a, 0xde,
];
const BASE_POINT2_Y: [u8; 32] = [
    0x30, 0xe2, 0xfe, 0xb3, 0x8d, 0x82, 0x4e, 0x0e, 0xa2, 0x95, 0x2f, 0x2a, 0x48, 0x5b, 0xbc, 0xdd,
    0x4c, 0x72, 0x8a, 0x74, 0xf4, 0xfa, 0xc7, 0xdc, 0x0d, 0xc9, 0x90, 0x8d, 0x9a, 0x8d, 0xc1, 0xa4,
];

use p256::NistP256;

lazy_static::lazy_static! {
    static ref BASE_POINT2_ENCODED: EncodedPoint<NistP256> = {
        let mut g = [0u8; 65];
        g[0] = 0x04;
        g[1..33].copy_from_slice(&BASE_POINT2_X);
        g[33..].copy_from_slice(&BASE_POINT2_Y);
        EncodedPoint::from_bytes(&g).unwrap()
    };

    static ref BASE_POINT2: AffinePoint = AffinePoint::from_encoded_point(&BASE_POINT2_ENCODED).unwrap();
}

#[test]
fn scalar_test() {
    let a: ScalarType = ScalarTrait::random_scalar();
    let b: ScalarType = ScalarTrait::random_scalar();

    let c1 = a.data * b.data;
    let c2 = a * b;
    assert_eq!(c1, c2.data);

    let c1 = a.data + b.data;
    let c2 = a + b;
    assert_eq!(c1, c2.data);

    let c1 = a.data - b.data;
    let c2 = a - b;
    assert_eq!(c1, c2.data);

    let c1 = -b.data;
    let c2 = -b;
    assert_eq!(c1, c2.data);
}

#[test]
fn point_test() {
    let g = PointType::generator();

    let a: ScalarType = ScalarTrait::random_scalar();
    let a_p: PointType = a * g;
    let b: ScalarType = ScalarTrait::random_scalar();
    let b_p: PointType = b * g;
    let c: ScalarType = ScalarTrait::random_scalar();
    let c_p: PointType = c * g;

    let add = a + b + c;
    let c1 = add * g;
    let c2 = a_p + b_p + c_p;
    assert_eq!(c1, c2);
}

#[test]
fn point_zero_test() {
    let g = PointType::generator();
    let inf_p = PointType::default();

    assert_eq!(inf_p, inf_p + inf_p);

    let a: ScalarType = ScalarTrait::zero();
    let a_p: PointType = a * g;
    let b: ScalarType = ScalarTrait::random_scalar();
    let b_p: PointType = b * g;
    let c: ScalarType = ScalarTrait::random_scalar();
    let c_p: PointType = c * g;

    assert_eq!(a_p, inf_p);

    let add = a + b - c;

    let c1 = a * (add * g) * b;
    let c2 = a * (a_p + b_p - c_p) * b;
    assert_eq!(c1, c2);
}