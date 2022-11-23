module ctf::encode {
    
    // [*] Import dependencies
    use std::vector;

    use sui::event;
    use sui::object::{Self, UID};
    use sui::transfer;
    use sui::tx_context::{Self, TxContext};
 
    // [*] Structs
    struct ResourceObject has key, store {
        id : UID,
        balance: u128,
        q1: bool
    }
 
    struct Flag has copy, drop {
        user: address,
        flag: bool
    }
 
    // [*] Module initializer
    fun init(ctx: &mut TxContext) {
        transfer::share_object(ResourceObject {
            id: object::new(ctx),
            balance: 100,
            q1: false,
        })
    }
 
    // [*] Public functions
    public entry fun ctf_decode(data1 : vector<u64>, data2 : vector<u64>, resource_object: &mut ResourceObject, _ctx: &mut TxContext) {

        let encrypted_flag : vector<u64> = vector
                [9,12,9,9,9,21,0,0,
                10,3,7,17,14,23,24,17,
                0,17,9,13,25,17,25,19,
                6,8,4,4,9,4,0,4,
                4,4,19,12,12,1,10,1,
                25,9,11,9,5,25,14,13,
                4,21,8,1,25,25,9,0,
                15,9,2,9,19,21,1,14,
                24,20,8,1,2,1,21,5];

        if (ctf_encode(data1, data2) == encrypted_flag) {
            if (!resource_object.q1) {
                resource_object.q1 = true;
            }
        }

    }

    fun ctf_encode(data1 : vector<u64>, data2 : vector<u64>) : vector<u64> {
        
        let input1 = copy data1;
        let plaintext = &mut input1;
        let plaintext_length = vector::length(plaintext);
        assert!(plaintext_length > 3, 0);

        if ( plaintext_length % 3 != 0) {
            if (3 - (plaintext_length % 3) == 2) {
                vector::push_back(plaintext, 0);
                vector::push_back(plaintext, 0);
                plaintext_length = plaintext_length + 2;
            }
            else {
                vector::push_back(plaintext, 0);
                plaintext_length = plaintext_length + 1;
            }
        };

        let complete_plaintext = vector::empty<u64>();
        vector::push_back(&mut complete_plaintext, 4);
        vector::push_back(&mut complete_plaintext, 15);
        vector::push_back(&mut complete_plaintext, 11);
        vector::push_back(&mut complete_plaintext, 0);
        vector::push_back(&mut complete_plaintext, 13);
        vector::push_back(&mut complete_plaintext, 4);
        vector::push_back(&mut complete_plaintext, 19);
        vector::push_back(&mut complete_plaintext, 19);
        vector::push_back(&mut complete_plaintext, 19);
        vector::append(&mut complete_plaintext, *plaintext);
        plaintext_length = plaintext_length + 9;

        let input2 = copy data2;
        let key = &mut input2;
        let a11 = *vector::borrow(key, 0);
        let a12 = *vector::borrow(key, 1);
        let a13 = *vector::borrow(key, 2);
        let a21 = *vector::borrow(key, 3);
        let a22 = *vector::borrow(key, 4);
        let a23 = *vector::borrow(key, 5);
        let a31 = *vector::borrow(key, 6);
        let a32 = *vector::borrow(key, 7);
        let a33 = *vector::borrow(key, 8);
        
        assert!(vector::length(key) == 9, 0);
        
        let i : u64 = 0;
        let ciphertext = vector::empty<u64>();
        while (i < plaintext_length) {
            let p11 = *vector::borrow(&mut complete_plaintext, i+0);
            let p21 = *vector::borrow(&mut complete_plaintext, i+1);
            let p31 = *vector::borrow(&mut complete_plaintext, i+2);

            let c11 = ( (a11 * p11) + (a12 * p21) + (a13 * p31) ) % 26;
            let c21 = ( (a21 * p11) + (a22 * p21) + (a23 * p31) ) % 26;
            let c31 = ( (a31 * p11) + (a32 * p21) + (a33 * p31) ) % 26;

            vector::push_back(&mut ciphertext, c11);
            vector::push_back(&mut ciphertext, c21);
            vector::push_back(&mut ciphertext, c31);

            i = i + 3;
        };

        ciphertext
        
    }

    public entry fun get_flag(resource_object: &ResourceObject, ctx: &mut TxContext) {
        if (resource_object.q1) {
            event::emit(Flag { user: tx_context::sender(ctx), flag: true })
        }
    }
}
