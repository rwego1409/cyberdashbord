// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract AuthorizationRegistry {
    struct Consent {
        address requester;
        string target;
        uint256 validUntil;
    }

    mapping(bytes32 => Consent) public consents;

    event ConsentGranted(bytes32 indexed consentId, address indexed requester, string target, uint256 validUntil);

    function grantConsent(bytes32 consentId, string calldata target, uint256 validUntil) external {
        require(validUntil > block.timestamp, "validUntil must be future");
        consents[consentId] = Consent(msg.sender, target, validUntil);
        emit ConsentGranted(consentId, msg.sender, target, validUntil);
    }

    function isConsentValid(bytes32 consentId) external view returns (bool) {
        Consent memory consent = consents[consentId];
        return consent.requester != address(0) && consent.validUntil >= block.timestamp;
    }
}

