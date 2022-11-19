// SPDX-License-Identifier: MIT
pragma solidity ^0.8.4;

import {ERC1155STF} from "@rage/utils/ERC1155STF.sol";
import {ERC1155TokenReceiver} from "@keep/KeepToken.sol";
import {SelfPermit} from "@base/src/utils/SelfPermit.sol";
import {ERC1155B} from "@base/src/tokens/ERC1155/ERC1155B.sol";
import {ReentrancyGuard} from "@base/src/utils/ReentrancyGuard.sol";
import {SafeTransferLib} from "@base/src/utils/SafeTransferLib.sol";
import {SafeMulticallable} from "@base/src/utils/SafeMulticallable.sol";

/// @title Lex Locker
/// @notice Law-enabled locker for ETH and any token (ERC20/721/1155).

enum Standard {
    ETH,
    ERC20,
    ERC721,
    ERC1155
}

struct Locker {
    address from;
    address oracle;
    address asset;
    Standard std;
    uint88 tokenId;
    uint208 deposit;
    uint32 deadline;
    uint8 milestone;
    bool frozen;
}

/// @author z0r0z.eth
contract LexLocker is
    ERC1155TokenReceiver,
    SelfPermit,
    ERC1155B,
    ReentrancyGuard,
    SafeMulticallable
{
    /// -----------------------------------------------------------------------
    /// Library Usage
    /// -----------------------------------------------------------------------

    using SafeTransferLib for address;

    /// -----------------------------------------------------------------------
    /// Events
    /// -----------------------------------------------------------------------

    event Deposit(
        address operator,
        uint256 indexed locker,
        address indexed from,
        address indexed to,
        address oracle,
        address asset,
        Standard std,
        uint88 tokenId,
        uint208[] amounts,
        uint32 deadline,
        bytes32 details
    );

    event Release(address operator, uint256 indexed locker);

    event Withdraw(address operator, uint256 indexed locker);

    event Freeze(address operator, uint256 indexed locker, bytes32 details);

    event Unfreeze(
        address operator,
        uint256 indexed locker,
        uint256 depositorAward,
        uint256 depositeeAward,
        bytes32 details
    );

    event Register(address operator, address indexed oracle, uint256 rate);

    /// -----------------------------------------------------------------------
    /// Custom Errors
    /// -----------------------------------------------------------------------

    error Overflow();

    error InvalidETHTribute();

    error DeadlinePending();

    error Frozen();

    error NotFrozen();

    error InvalidAwards();

    error InvalidRate();

    error InvalidSig();

    /// -----------------------------------------------------------------------
    /// Locker Storage
    /// -----------------------------------------------------------------------

    ERC1155B internal immutable uriFetcher;

    Locker[] public lockers;

    mapping(uint256 => uint256[]) public schedules;

    mapping(address => uint256) public oracles;

    /// -----------------------------------------------------------------------
    /// EIP-712 Storage/Logic
    /// -----------------------------------------------------------------------

    uint256 internal immutable INITIAL_CHAIN_ID;

    bytes32 internal immutable INITIAL_DOMAIN_SEPARATOR;

    bytes32 internal constant MALLEABILITY_THRESHOLD =
        0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0;

    mapping(address => uint256) public nonces;

    function DOMAIN_SEPARATOR() public view virtual returns (bytes32) {
        return
            block.chainid == INITIAL_CHAIN_ID
                ? INITIAL_DOMAIN_SEPARATOR
                : _computeDomainSeparator();
    }

    function _computeDomainSeparator() internal view virtual returns (bytes32) {
        return
            keccak256(
                abi.encode(
                    keccak256(
                        "EIP712Domain(string name,string version,uint256 chainId,address verifyingContract)"
                    ),
                    keccak256(bytes("Lex Locker")),
                    keccak256("1"),
                    block.chainid,
                    address(this)
                )
            );
    }

    /// -----------------------------------------------------------------------
    /// Constructor
    /// -----------------------------------------------------------------------

    /// @notice Create contract.
    /// @param _uriFetcher Metadata extension.
    constructor(ERC1155B _uriFetcher) payable {
        uriFetcher = _uriFetcher;
        INITIAL_CHAIN_ID = block.chainid;
        INITIAL_DOMAIN_SEPARATOR = _computeDomainSeparator();
    }

    /// -----------------------------------------------------------------------
    /// Locker Logic
    /// -----------------------------------------------------------------------

    /// @notice ID metadata fetcher.
    /// @param id ID to fetch from.
    /// @return tokenURI Metadata.
    function uri(
        uint256 id
    ) public view virtual override returns (string memory) {
        return uriFetcher.uri(id);
    }

    /// @notice Locker maker mechanism.
    /// @param from The account to pull.
    /// @param to The account to release to.
    /// @param oracle The subjective provider.
    /// @param asset The token address for locker.
    /// @param std The EIP interface for locker `asset`.
    /// @param tokenId The ID of `asset` to make deposit in.
    /// @param amounts The amounts of `asset` to make deposit in.
    /// @param deadline The unix time at which the escrowed locker will expire.
    /// @param details The deal content or other legal context for each locker.
    /// @return locker The locker ID assigned incrementally for each depositor.
    /// @dev The `tokenId` will be used where locker `asset` follows ERC721 or ERC1155.
    /// @param v Must produce valid secp256k1 signature from the `owner` along with `r` and `s`.
    /// @param r Must produce valid secp256k1 signature from the `owner` along with `v` and `s`.
    /// @param s Must produce valid secp256k1 signature from the `owner` along with `r` and `v`.
    /// @param countersigned Whether to include on-chain recovery of receiver account signature.
    function deposit(
        address from,
        address to,
        address oracle,
        address asset,
        Standard std,
        uint88 tokenId,
        uint208[] calldata amounts,
        uint32 deadline,
        bytes32 details,
        uint8 v,
        bytes32 r,
        bytes32 s,
        bool countersigned
    ) public payable virtual nonReentrant returns (uint256 locker) {
        if (msg.sender != from) {
            // Unchecked because the only math done is incrementing
            // the depositor's nonce which can't realistically overflow.
            unchecked {
                bytes32 hash = keccak256(
                    abi.encodePacked(
                        "\x19\x01",
                        DOMAIN_SEPARATOR(),
                        keccak256(
                            abi.encode(
                                keccak256(
                                    "Deposit(address to,address oracle,address asset,uint8 std,uint88 tokenId,uint208[] calldata amounts,uint32 deadline,bytes32 details,bool countersigned,uint256 nonce)"
                                ),
                                to,
                                oracle,
                                asset,
                                std,
                                tokenId,
                                amounts,
                                deadline,
                                details,
                                countersigned,
                                nonces[from]++
                            )
                        )
                    )
                );

                // Check depositor signature.
                _recoverSig(hash, from, v, r, s);

                // If applicable, check countersignature.
                if (countersigned) _recoverSig(hash, to, v, r, s);
            }
        }

        uint208 sum;

        for (uint256 i; i < amounts.length; ) {
            if ((sum += amounts[i]) >= (1 << 208)) revert Overflow();

            // An array can't have a total length
            // larger than the max uint256 value.
            unchecked {
                ++i;
            }
        }

        locker = lockers.length;

        schedules[locker] = amounts;

        lockers.push(
            Locker({
                from: from,
                oracle: oracle,
                asset: asset,
                std: std,
                tokenId: tokenId,
                deposit: sum,
                deadline: deadline,
                milestone: 0,
                frozen: false
            })
        );

        _mint(to, locker, "");

        // If user attaches ETH, handle value.
        // Otherwise, token transfer is made.
        if (msg.value != 0) {
            if (msg.value != sum || std != Standard.ETH)
                revert InvalidETHTribute();
        } else if (std == Standard.ERC20) {
            asset.safeTransferFrom(from, address(this), sum);
        } else if (std == Standard.ERC721) {
            asset.safeTransferFrom(from, address(this), tokenId);
        } else if (std != Standard.ETH) {
            ERC1155STF(asset).safeTransferFrom(
                from,
                address(this),
                tokenId,
                sum,
                ""
            );
        }

        emit Deposit(
            msg.sender,
            locker, // Locker deposit ID.
            from, // Locker proposer.
            to,
            oracle,
            asset,
            std,
            tokenId,
            amounts,
            deadline,
            details
        );
    }

    /// @notice Locker release mechanism.
    /// @param user The address for verification.
    /// @param locker The ID to activate release for.
    /// @param v Must produce valid secp256k1 signature from the `owner` along with `r` and `s`.
    /// @param r Must produce valid secp256k1 signature from the `owner` along with `v` and `s`.
    /// @param s Must produce valid secp256k1 signature from the `owner` along with `r` and `v`.
    /// @dev Calls are permissioned to the locker maker or their oracle.
    function release(
        address user,
        uint256 locker,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public payable virtual nonReentrant {
        // Fetch locker details.
        Locker storage lock = lockers[locker];

        if (msg.sender != lock.from)
            if (msg.sender != lock.oracle) {
                // Unchecked because the only math done is incrementing
                // the user's nonce which can't realistically overflow.
                unchecked {
                    bytes32 hash = keccak256(
                        abi.encodePacked(
                            "\x19\x01",
                            DOMAIN_SEPARATOR(),
                            keccak256(
                                abi.encode(
                                    keccak256(
                                        "Release(uint256 locker,uint256 nonce)"
                                    ),
                                    locker,
                                    nonces[user]++
                                )
                            )
                        )
                    );

                    // Check signature recovery.
                    _recoverSig(hash, user, v, r, s);
                }
            }

        // Check whether frozen.
        if (lock.frozen) revert Frozen();

        // Fetch locker receiver.
        address to = ownerOf[locker];

        // Fetch milestone amount.
        uint256 amount = schedules[locker][lock.milestone];

        if (lock.std == Standard.ETH) to.safeTransferETH(amount);
        else if (lock.std == Standard.ERC20)
            lock.asset.safeTransfer(to, amount);
        else if (lock.std == Standard.ERC721)
            lock.asset.safeTransferFrom(address(this), to, lock.tokenId);
        else
            ERC1155STF(lock.asset).safeTransferFrom(
                address(this),
                to,
                lock.tokenId,
                amount,
                ""
            );

        // Unchecked because milestone
        // won't exceed total deposit,
        // and milestone step won't
        // realistically overflow.
        unchecked {
            lock.deposit -= uint208(amount);

            ++lock.milestone;
        }

        // Delete locker so it can't be replayed.
        // Unchecked because schedule is positive.
        unchecked {
            if (lock.milestone == schedules[locker].length - 1)
                delete lockers[locker];
        }

        emit Release(msg.sender, locker);
    }

    /// @notice Timed locker withdrawal.
    /// @param user The address for verification.
    /// @param locker The ID to activate withdrawal for.
    /// @param v Must produce valid secp256k1 signature from the `owner` along with `r` and `s`.
    /// @param r Must produce valid secp256k1 signature from the `owner` along with `v` and `s`.
    /// @param s Must produce valid secp256k1 signature from the `owner` along with `r` and `v`.
    function withdraw(
        address user,
        uint256 locker,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public payable virtual nonReentrant {
        // Fetch locker details.
        Locker storage lock = lockers[locker];

        if (msg.sender != lock.from)
            if (msg.sender != lock.oracle) {
                // Unchecked because the only math done is incrementing
                // the user's nonce which can't realistically overflow.
                unchecked {
                    bytes32 hash = keccak256(
                        abi.encodePacked(
                            "\x19\x01",
                            DOMAIN_SEPARATOR(),
                            keccak256(
                                abi.encode(
                                    keccak256(
                                        "Withdraw(uint256 locker,uint256 nonce)"
                                    ),
                                    locker,
                                    nonces[user]++
                                )
                            )
                        )
                    );

                    // Check signature recovery.
                    _recoverSig(hash, user, v, r, s);
                }
            }

        // Check whether frozen.
        if (lock.frozen) revert Frozen();

        // Check release deadline.
        if (block.timestamp <= lock.deadline) revert DeadlinePending();

        if (lock.std == Standard.ETH) lock.from.safeTransferETH(lock.deposit);
        else if (lock.std == Standard.ERC20)
            lock.asset.safeTransfer(msg.sender, lock.deposit);
        else if (lock.std == Standard.ERC721)
            lock.asset.safeTransferFrom(address(this), lock.from, lock.tokenId);
        else
            ERC1155STF(lock.asset).safeTransferFrom(
                address(this),
                lock.from,
                lock.tokenId,
                lock.deposit,
                ""
            );

        // Delete locker so it can't be replayed.
        delete lockers[locker];

        emit Withdraw(msg.sender, locker);
    }

    /// @notice Locker freeze mechanism.
    /// @param user The address for verification.
    /// @param locker The ID to activate freeze for.
    /// @param details The content or context for freeze.
    /// @param v Must produce valid secp256k1 signature from the `owner` along with `r` and `s`.
    /// @param r Must produce valid secp256k1 signature from the `owner` along with `v` and `s`.
    /// @param s Must produce valid secp256k1 signature from the `owner` along with `r` and `v`.
    /// @dev Calls are permissioned to the locker parties.
    function freeze(
        address user,
        uint256 locker,
        bytes32 details,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public payable virtual nonReentrant {
        // Fetch locker details.
        Locker storage lock = lockers[locker];

        // Fetch locker receiver.
        address to = ownerOf[locker];

        if (msg.sender != lock.from)
            if (msg.sender != to) {
                // Unchecked because the only math done is incrementing
                // the user's nonce which can't realistically overflow.
                unchecked {
                    bytes32 hash = keccak256(
                        abi.encodePacked(
                            "\x19\x01",
                            DOMAIN_SEPARATOR(),
                            keccak256(
                                abi.encode(
                                    keccak256(
                                        "Withdraw(uint256 locker,bytes32 details,uint256 nonce)"
                                    ),
                                    locker,
                                    details,
                                    nonces[user]++
                                )
                            )
                        )
                    );

                    // Check signature recovery.
                    _recoverSig(hash, user, v, r, s);
                }

                if (user != lock.from)
                    if (user != to) revert InvalidSig();
            }

        // Set freezer.
        lock.frozen = true;

        emit Freeze(msg.sender, locker, details);
    }

    /// @notice Locker unfreeze mechanism.
    /// @param locker The ID to activate freeze for.
    /// @param depositorAward The amount released to depositor.
    /// @param depositeeAward The amount released to depositee.
    /// @param details The content or context for locker release.
    /// @param v Must produce valid secp256k1 signature from the `owner` along with `r` and `s`.
    /// @param r Must produce valid secp256k1 signature from the `owner` along with `v` and `s`.
    /// @param s Must produce valid secp256k1 signature from the `owner` along with `r` and `v`.
    /// @dev Calls are permissioned to the locker oracle.
    function unfreeze(
        uint256 locker,
        uint256 depositorAward,
        uint256 depositeeAward,
        bytes32 details,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public payable virtual nonReentrant {
        // Fetch locker details.
        Locker storage lock = lockers[locker];

        if (msg.sender != lock.oracle) {
            bytes32 hash = keccak256(
                abi.encodePacked(
                    "\x19\x01",
                    DOMAIN_SEPARATOR(),
                    keccak256(
                        abi.encode(
                            keccak256(
                                "Unfreeze(uint256 locker,uint256 depositorAward,uint256 depositeeAward,bytes32 details)"
                            ),
                            locker,
                            depositorAward,
                            depositeeAward,
                            details
                        )
                    )
                )
            );

            // Check signature recovery.
            _recoverSig(hash, lock.oracle, v, r, s);
        }

        // Check whether frozen.
        if (!lock.frozen) revert NotFrozen();

        uint256 amount = lock.deposit;

        // Unchecked because `amount` provides bound.
        unchecked {
            if (depositorAward + depositeeAward != amount)
                revert InvalidAwards();
        }

        // Price oracle fee into awards.
        uint256 fee = oracles[msg.sender];

        assembly {
            fee := div(amount, fee)

            fee := div(fee, 2)
        }

        depositorAward -= fee;

        depositeeAward -= fee;

        // Fetch locker receiver.
        address to = ownerOf[locker];

        if (lock.std == Standard.ETH)
            if (depositorAward != 0) lock.from.safeTransferETH(depositorAward);
        if (depositeeAward != 0) to.safeTransferETH(depositeeAward);
        else if (lock.std == Standard.ERC20)
            if (depositorAward != 0)
                lock.asset.safeTransfer(lock.from, depositorAward);
        if (depositeeAward != 0) lock.asset.safeTransfer(to, depositeeAward);
        else if (lock.std == Standard.ERC721)
            lock.asset.safeTransferFrom(
                address(this),
                depositorAward != 0 ? lock.from : to,
                lock.tokenId
            );
        else if (depositorAward != 0)
            ERC1155STF(lock.asset).safeTransferFrom(
                address(this),
                lock.from,
                lock.tokenId,
                depositorAward,
                ""
            );
        if (depositeeAward != 0)
            ERC1155STF(lock.asset).safeTransferFrom(
                address(this),
                to,
                lock.tokenId,
                depositeeAward,
                ""
            );

        emit Unfreeze(
            msg.sender,
            locker,
            depositorAward,
            depositeeAward,
            details
        );
    }

    /// @notice Oracle registration mechanism.
    /// @param user The address for verification.
    /// @param rate The amount to divide remainder against.
    /// @param v Must produce valid secp256k1 signature from the `owner` along with `r` and `s`.
    /// @param r Must produce valid secp256k1 signature from the `owner` along with `v` and `s`.
    /// @param s Must produce valid secp256k1 signature from the `owner` along with `r` and `v`.
    function register(
        address user,
        uint256 rate,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) public payable virtual {
        if (msg.sender != user) {
            // Unchecked because the only math done is incrementing
            // the user's nonce which can't realistically overflow.
            unchecked {
                bytes32 hash = keccak256(
                    abi.encodePacked(
                        "\x19\x01",
                        DOMAIN_SEPARATOR(),
                        keccak256(
                            abi.encode(
                                keccak256("Register(uint256 rate)"),
                                rate,
                                nonces[user]++
                            )
                        )
                    )
                );

                // Check signature recovery.
                _recoverSig(hash, user, v, r, s);
            }
        }

        if (rate == 0) revert InvalidRate();

        oracles[user] = rate;

        emit Register(msg.sender, user, rate);
    }

    function _recoverSig(
        bytes32 hash,
        address user,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) internal view virtual {
        if (user == address(0)) revert InvalidSig();

        address signer;

        // Perform signature recovery via ecrecover.
        /// @solidity memory-safe-assembly
        assembly {
            // Copy the free memory pointer so that we can restore it later.
            let m := mload(0x40)

            // If `s` in lower half order, such that the signature is not malleable.
            if iszero(gt(s, MALLEABILITY_THRESHOLD)) {
                mstore(0x00, hash)
                mstore(0x20, v)
                mstore(0x40, r)
                mstore(0x60, s)
                pop(
                    staticcall(
                        gas(), // Amount of gas left for the transaction.
                        0x01, // Address of `ecrecover`.
                        0x00, // Start of input.
                        0x80, // Size of input.
                        0x40, // Start of output.
                        0x20 // Size of output.
                    )
                )
                // Restore the zero slot.
                mstore(0x60, 0)
                // `returndatasize()` will be `0x20` upon success, and `0x00` otherwise.
                signer := mload(sub(0x60, returndatasize()))
            }
            // Restore the free memory pointer.
            mstore(0x40, m)
        }

        // If recovery doesn't match `user`, verify contract signature with ERC1271.
        if (user != signer) {
            bool valid;

            /// @solidity memory-safe-assembly
            assembly {
                // Load the free memory pointer.
                // Simply using the free memory usually costs less if many slots are needed.
                let m := mload(0x40)

                // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
                let f := shl(224, 0x1626ba7e)
                // Write the abi-encoded calldata into memory, beginning with the function selector.
                mstore(m, f) // `bytes4(keccak256("isValidSignature(bytes32,bytes)"))`.
                mstore(add(m, 0x04), hash)
                mstore(add(m, 0x24), 0x40) // The offset of the `signature` in the calldata.
                mstore(add(m, 0x44), 65) // Store the length of the signature.
                mstore(add(m, 0x64), r) // Store `r` of the signature.
                mstore(add(m, 0x84), s) // Store `s` of the signature.
                mstore8(add(m, 0xa4), v) // Store `v` of the signature.

                valid := and(
                    and(
                        // Whether the returndata is the magic value `0x1626ba7e` (left-aligned).
                        eq(mload(0x00), f),
                        // Whether the returndata is exactly 0x20 bytes (1 word) long.
                        eq(returndatasize(), 0x20)
                    ),
                    // Whether the staticcall does not revert.
                    // This must be placed at the end of the `and` clause,
                    // as the arguments are evaluated from right to left.
                    staticcall(
                        gas(), // Remaining gas.
                        user, // The `user` address.
                        m, // Offset of calldata in memory.
                        0xa5, // Length of calldata in memory.
                        0x00, // Offset of returndata.
                        0x20 // Length of returndata to write.
                    )
                )
            }

            if (!valid) revert InvalidSig();
        }
    }
}
