#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use pallet::*;

#[frame_support::pallet(dev_mode)]
pub mod pallet {
	use alloc::{string::String, vec::Vec};
	use frame_support::{pallet_prelude::*, sp_io::hashing::keccak_256};
	use frame_system::pallet_prelude::*;

	#[derive(Debug, Copy, Clone, Eq, PartialEq, Hash, Encode, Decode, MaxEncodedLen, TypeInfo)]
	pub enum EntityType {
		Issuer,
		Subject,
	}

	#[derive(Debug, Clone, Eq, PartialEq, Hash, Encode, Decode, TypeInfo)]
	pub struct Entity<BlockNumber> {
		entity_type: EntityType,
		issuer: String,
		subject: String,
		public_key: Vec<u8>,
		serial_number: u64,
		validity: BlockNumber,
		exists: bool,
	}

	#[pallet::pallet]
	pub struct Pallet<T>(_);

	#[pallet::config]
	pub trait Config: frame_system::Config {
		type RuntimeEvent: From<Event<Self>> + IsType<<Self as frame_system::Config>::RuntimeEvent>;

		#[pallet::constant]
		type SecondsPerBlock: Get<u32>;
	}

	#[pallet::storage]
	#[pallet::getter(fn something)]
	pub type Entities<T> = StorageMap<_, Twox64Concat, [u8; 32], Entity<BlockNumberFor<T>>>;

	#[pallet::event]
	#[pallet::generate_deposit(pub(super) fn deposit_event)]
	pub enum Event<T: Config> {
		CertificateIssued {
			version: u32,
			serial_number: u64,
			issuer: String,
			validity: BlockNumberFor<T>,
			subject: String,
			public_key: Vec<u8>,
			signature: Vec<u8>,
		},
	}

	#[pallet::error]
	pub enum Error<T> {
		EntityAlreadyExists,
		IssuerNotFound,
		EntityNotIssuer,
		InvalidSignature,
		EntityNotFound,
	}

	#[pallet::call]
	impl<T: Config> Pallet<T> {
		/// Registers a new entity in the registry
		/// `issuer` The identifier of the entity that issued the certificate
		/// `subject` The identifier of the entity being registered, may be the same as the issuer
		/// `public_key` The public key of the entity being registered
		/// `signature` The signature of the hash of the subject and public key with the issuer's
		/// private key
		#[pallet::call_index(0)]
		#[pallet::weight(0)]
		pub fn register(
			origin: OriginFor<T>,
			issuer: String,
			subject: String,
			public_key: Vec<u8>,
			signature: Vec<u8>,
		) -> DispatchResult {
			let _who = ensure_signed(origin)?;

			let issuer_hash = keccak_256(issuer.as_bytes());
			let subject_hash = keccak_256(subject.as_bytes());

			let serial_number;
			let entity_type;
			let message_hash = keccak_256(&{
				let mut data = Vec::with_capacity(subject.as_bytes().len() + public_key.len());
				data.extend_from_slice(subject.as_bytes());
				data.extend_from_slice(&public_key);
				data
			});

			// ensure that the subject identifier is not already registered
			ensure!(!Entities::<T>::contains_key(&subject_hash), Error::<T>::EntityAlreadyExists);

			if issuer_hash != subject_hash {
				// Certificate issued by another entity
				// ensure that the issuer is registered, and a valid issuer
				let Some(mut issuer_entity) = Entities::<T>::get(&issuer_hash) else {
					return Err(Error::<T>::IssuerNotFound.into());
				};
				ensure!(
					issuer_entity.entity_type == EntityType::Issuer,
					Error::<T>::EntityNotIssuer
				);
				ensure!(
					Self::verify_signature(&message_hash, &public_key, &signature),
					Error::<T>::InvalidSignature
				);
				issuer_entity.serial_number += 1;
				serial_number = issuer_entity.serial_number;
				entity_type = EntityType::Subject;
				Entities::<T>::insert(issuer_hash, issuer_entity);
			} else {
				// Self-signed certificate
				ensure!(
					Self::verify_signature(&message_hash, &public_key, &signature),
					Error::<T>::InvalidSignature
				);
				serial_number = 0;
				entity_type = EntityType::Issuer;
			}

			// Set the validity of the certificate to expire 1 year from now
			let validity = frame_system::Pallet::<T>::block_number() +
				BlockNumberFor::<T>::from(365 * 24 * 3600 / T::SecondsPerBlock::get());

			// Record the entity details in the registry
			Entities::<T>::insert(
				subject_hash,
				Entity {
					entity_type,
					issuer: issuer.clone(),
					subject: subject.clone(),
					public_key: public_key.clone(),
					serial_number,
					validity,
					exists: true,
				},
			);

			// Emit an event that contains the certificate
			Self::deposit_event(Event::CertificateIssued {
				version: 2,
				serial_number,
				issuer,
				validity,
				subject,
				public_key,
				signature,
			});

			Ok(())
		}

		/// Updates the public key and validity of an entity's certificate
		/// `subject` The identifier of the entity being renewed
		/// `public_key` The new public key of the entity being renewed
		/// `signature` The signature of the hash of the subject and new public key with the
		/// issuer's private key
		#[pallet::call_index(1)]
		#[pallet::weight(0)]
		pub fn renew(
			origin: OriginFor<T>,
			subject: String,
			public_key: Vec<u8>,
			signature: Vec<u8>,
		) -> DispatchResult {
			let _who = ensure_signed(origin)?;

			// ensure the entity has registered
			let subject_hash = keccak_256(subject.as_bytes());
			let Some(mut entity) = Entities::<T>::get(&subject_hash) else {
				return Err(Error::<T>::EntityNotFound.into());
			};

			let issuer_key;
			let maybe_issuer_entity;
			if entity.entity_type == EntityType::Issuer {
				// if the entity is an issuer, use its own public key to verify the signature
				issuer_key = entity.public_key;
				maybe_issuer_entity = None;
			} else {
				// else get the issuer's public key to verify the signature
				let issuer_hash = keccak_256(entity.issuer.as_bytes());
				let Some(issuer_entity) = Entities::<T>::get(&issuer_hash) else {
					return Err(Error::<T>::IssuerNotFound.into());
				};
				issuer_key = issuer_entity.public_key.clone();
				maybe_issuer_entity = Some((issuer_hash, issuer_entity));
			}

			// ensure the signature is valid
			let message_hash = keccak_256(&{
				let mut data = Vec::with_capacity(subject.as_bytes().len() + public_key.len());
				data.extend_from_slice(subject.as_bytes());
				data.extend_from_slice(&public_key);
				data
			});
			ensure!(
				Self::verify_signature(&message_hash, &issuer_key, &signature),
				Error::<T>::InvalidSignature
			);

			// update the entity's public key
			entity.public_key = public_key;

			// update the entity's validity
			entity.validity = frame_system::Pallet::<T>::block_number() +
				BlockNumberFor::<T>::from(365 * 24 * 3600 / T::SecondsPerBlock::get());

			// increment the serial number of the issuer and the entity
			if entity.entity_type == EntityType::Issuer {
				entity.serial_number += 1;
			} else {
				let (issuer_hash, mut issuer_entity) =
					maybe_issuer_entity.expect("Set above in identical condition; qed");
				issuer_entity.serial_number += 1;
				entity.serial_number = issuer_entity.serial_number;
				Entities::<T>::insert(issuer_hash, issuer_entity);
			}
			Entities::<T>::insert(subject_hash, entity.clone());

			// emit the new certificate as an event
			Self::deposit_event(Event::CertificateIssued {
				version: 2,
				serial_number: entity.serial_number,
				issuer: entity.issuer,
				validity: entity.validity,
				subject: entity.subject,
				public_key: entity.public_key.clone(),
				signature,
			});

			Ok(())
		}

		#[pallet::call_index(2)]
		#[pallet::weight(0)]
		pub fn revoke(
			origin: OriginFor<T>,
			subject: String,
			nonce: String,
			signature: Vec<u8>,
		) -> DispatchResult {
			let _who = ensure_signed(origin)?;

			// ensure the entity has registered
			let subject_hash = keccak_256(subject.as_bytes());
			let message_hash = keccak_256(&{
				let mut data =
					Vec::with_capacity(subject.as_bytes().len() + nonce.as_bytes().len());
				data.extend_from_slice(subject.as_bytes());
				data.extend_from_slice(nonce.as_bytes());
				data
			});
			let Some(entity) = Entities::<T>::get(&subject_hash) else {
				return Err(Error::<T>::EntityNotFound.into());
			};

			// get the public key of the issuer to verify the signature
			let public_key = if entity.entity_type == EntityType::Issuer {
				let issuer_hash = keccak_256(entity.issuer.as_bytes());
				let Some(issuer_entity) = Entities::<T>::get(&issuer_hash) else {
					return Err(Error::<T>::IssuerNotFound.into());
				};
				issuer_entity.public_key
			} else {
				entity.public_key
			};

			ensure!(
				Self::verify_signature(&message_hash, &public_key, &signature),
				Error::<T>::InvalidSignature
			);

			Entities::<T>::remove(&subject_hash);

			Ok(())
		}
	}
}

impl<T: Config> Pallet<T> {
	fn verify_signature(_message_hash: &[u8], _public_key: &[u8], _signature: &[u8]) -> bool {
		return true;
	}
}
