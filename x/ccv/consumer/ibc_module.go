package consumer

import (
	"fmt"
	"strings"

	sdkerrors "cosmossdk.io/errors"
	sdkerrorstypes "github.com/cosmos/cosmos-sdk/types/errors"

	sdk "github.com/cosmos/cosmos-sdk/types"
	capabilitytypes "github.com/cosmos/cosmos-sdk/x/capability/types"
	channeltypes "github.com/cosmos/ibc-go/v7/modules/core/04-channel/types"
	porttypes "github.com/cosmos/ibc-go/v7/modules/core/05-port/types"
	host "github.com/cosmos/ibc-go/v7/modules/core/24-host"
	ibcexported "github.com/cosmos/ibc-go/v7/modules/core/exported"

	"github.com/cosmos/interchain-security/v3/x/ccv/consumer/keeper"
	consumertypes "github.com/cosmos/interchain-security/v3/x/ccv/consumer/types"
	"github.com/cosmos/interchain-security/v3/x/ccv/types"
)

// OnChanOpenInit implements the IBCModule interface
// this function is called by the relayer.
func (am AppModule) OnChanOpenInit(
	ctx sdk.Context,
	order channeltypes.Order,
	connectionHops []string,
	portID string,
	channelID string,
	chanCap *capabilitytypes.Capability,
	counterparty channeltypes.Counterparty,
	version string,
) (string, error) {
	// set to the default version if the provided version is empty according to the ICS26 spec
	// https://github.com/cosmos/ibc/blob/main/spec/core/ics-026-routing-module/README.md#technical-specification
	if strings.TrimSpace(version) == "" {
		version = types.Version
	}

	// ensure provider channel hasn't already been created
	if providerChannel, ok := am.keeper.GetProviderChannel(ctx); ok {
		return "", sdkerrors.Wrapf(types.ErrDuplicateChannel,
			"provider channel: %s already set", providerChannel)
	}

	// Validate parameters
	if err := validateCCVChannelParams(
		ctx, am.keeper, order, portID, version,
	); err != nil {
		return "", err
	}

	// ensure the counterparty port ID matches the expected provider port ID
	if counterparty.PortId != types.ProviderPortID {
		return "", sdkerrors.Wrapf(porttypes.ErrInvalidPort,
			"invalid counterparty port: %s, expected %s", counterparty.PortId, types.ProviderPortID)
	}

	// Claim channel capability passed back by IBC module
	if err := am.keeper.ClaimCapability(
		ctx, chanCap, host.ChannelCapabilityPath(portID, channelID),
	); err != nil {
		return "", err
	}

	if err := am.keeper.VerifyProviderChain(ctx, connectionHops); err != nil {
		return "", err
	}

	return version, nil
}

// validateCCVChannelParams validates a ccv channel
func validateCCVChannelParams(
	ctx sdk.Context,
	keeper keeper.Keeper,
	order channeltypes.Order,
	portID string,
	version string,
) error {
	// Only ordered channels allowed
	if order != channeltypes.ORDERED {
		return sdkerrors.Wrapf(channeltypes.ErrInvalidChannelOrdering, "expected %s channel, got %s ", channeltypes.ORDERED, order)
	}

	// the port ID must match the port ID the CCV module is bounded to
	boundPort := keeper.GetPort(ctx)
	if boundPort != portID {
		return sdkerrors.Wrapf(porttypes.ErrInvalidPort, "invalid port: %s, expected %s", portID, boundPort)
	}

	// the version must match the expected version
	if version != types.Version {
		return sdkerrors.Wrapf(types.ErrInvalidVersion, "got %s, expected %s", version, types.Version)
	}
	return nil
}

// OnChanOpenTry implements the IBCModule interface
func (am AppModule) OnChanOpenTry(
	ctx sdk.Context,
	order channeltypes.Order,
	connectionHops []string,
	portID,
	channelID string,
	chanCap *capabilitytypes.Capability,
	counterparty channeltypes.Counterparty,
	counterpartyVersion string,
) (string, error) {
	return "", sdkerrors.Wrap(types.ErrInvalidChannelFlow, "channel handshake must be initiated by consumer chain")
}

// OnChanOpenAck implements the IBCModule interface
func (am AppModule) OnChanOpenAck(
	ctx sdk.Context,
	portID,
	channelID string,
	_ string, // Counter party channel ID is unused per spec
	counterpartyVersion string,
) error {
	// ensure provider channel has not already been created
	if providerChannel, ok := am.keeper.GetProviderChannel(ctx); ok {
		return sdkerrors.Wrapf(types.ErrDuplicateChannel,
			"provider channel: %s already established", providerChannel)
	}

	if counterpartyVersion != types.Version {
		return sdkerrors.Wrapf(types.ErrInvalidVersion,
			"invalid counterparty version: %s, expected %s", counterpartyVersion, types.Version)
	}

	// /////////////////////////////////////////////////
	// Initialize distribution token transfer channel

	// First check if an existing transfer channel exists, if this consumer was a previously standalone chain.
	if am.keeper.IsPrevStandaloneChain(ctx) {
		transChannelID := am.keeper.GetStandaloneTransferChannelID(ctx)
		found := am.keeper.TransferChannelExists(ctx, transChannelID)
		if found {
			// If existing transfer channel is found, persist that channel ID and return
			am.keeper.SetDistributionTransmissionChannel(ctx, transChannelID)
			return nil
		}
	}
	return nil
}

// OnChanOpenConfirm implements the IBCModule interface
func (am AppModule) OnChanOpenConfirm(
	ctx sdk.Context,
	portID,
	channelID string,
) error {
	return sdkerrors.Wrap(types.ErrInvalidChannelFlow, "channel handshake must be initiated by consumer chain")
}

// OnChanCloseInit implements the IBCModule interface
func (am AppModule) OnChanCloseInit(
	ctx sdk.Context,
	portID,
	channelID string,
) error {
	// allow relayers to close duplicate OPEN channels, if the provider channel has already been established
	if providerChannel, ok := am.keeper.GetProviderChannel(ctx); ok && providerChannel != channelID {
		return nil
	}
	return sdkerrors.Wrap(sdkerrorstypes.ErrInvalidRequest, "user cannot close channel")
}

// OnChanCloseConfirm implements the IBCModule interface
func (am AppModule) OnChanCloseConfirm(
	ctx sdk.Context,
	portID,
	channelID string,
) error {
	return nil
}

// OnRecvPacket implements the IBCModule interface. A successful acknowledgement
// is returned if the packet data is successfully decoded and the receive application
// logic returns without error.
func (am AppModule) OnRecvPacket(
	ctx sdk.Context,
	packet channeltypes.Packet,
	_ sdk.AccAddress,
) ibcexported.Acknowledgement {
	var (
		ack  ibcexported.Acknowledgement
		data types.ValidatorSetChangePacketData
	)
	if err := types.ModuleCdc.UnmarshalJSON(packet.GetData(), &data); err != nil {
		errAck := channeltypes.NewErrorAcknowledgement(fmt.Errorf("cannot unmarshal CCV packet data"))
		ack = &errAck
	} else {
		ack = am.keeper.OnRecvVSCPacket(ctx, packet, data)
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypePacket,
			sdk.NewAttribute(sdk.AttributeKeyModule, consumertypes.ModuleName),
			sdk.NewAttribute(types.AttributeKeyAckSuccess, fmt.Sprintf("%t", ack != nil)),
		),
	)

	return ack
}

// OnAcknowledgementPacket implements the IBCModule interface
func (am AppModule) OnAcknowledgementPacket(
	ctx sdk.Context,
	packet channeltypes.Packet,
	acknowledgement []byte,
	_ sdk.AccAddress,
) error {
	var ack channeltypes.Acknowledgement
	if err := types.ModuleCdc.UnmarshalJSON(acknowledgement, &ack); err != nil {
		return sdkerrors.Wrapf(sdkerrorstypes.ErrUnknownRequest, "cannot unmarshal consumer packet acknowledgement: %v", err)
	}

	if err := am.keeper.OnAcknowledgementPacket(ctx, packet, ack); err != nil {
		return err
	}

	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypePacket,
			sdk.NewAttribute(sdk.AttributeKeyModule, consumertypes.ModuleName),
			sdk.NewAttribute(types.AttributeKeyAck, ack.String()),
		),
	)
	switch resp := ack.Response.(type) {
	case *channeltypes.Acknowledgement_Result:
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypePacket,
				sdk.NewAttribute(types.AttributeKeyAckSuccess, string(resp.Result)),
			),
		)
	case *channeltypes.Acknowledgement_Error:
		ctx.EventManager().EmitEvent(
			sdk.NewEvent(
				types.EventTypePacket,
				sdk.NewAttribute(types.AttributeKeyAckError, resp.Error),
			),
		)
	}
	return nil
}

// OnTimeoutPacket implements the IBCModule interface
// the CCV channel state is changed to CLOSED
// by the IBC module as the channel is ORDERED
func (am AppModule) OnTimeoutPacket(
	ctx sdk.Context,
	packet channeltypes.Packet,
	_ sdk.AccAddress,
) error {
	ctx.EventManager().EmitEvent(
		sdk.NewEvent(
			types.EventTypeTimeout,
			sdk.NewAttribute(sdk.AttributeKeyModule, consumertypes.ModuleName),
		),
	)

	return nil
}
