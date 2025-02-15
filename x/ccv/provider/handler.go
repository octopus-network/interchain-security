package provider

import (
	sdkerrors "cosmossdk.io/errors"
	sdk "github.com/cosmos/cosmos-sdk/types"
	sdkerrorstypes "github.com/cosmos/cosmos-sdk/types/errors"

	"github.com/cosmos/interchain-security/v3/x/ccv/provider/keeper"
	"github.com/cosmos/interchain-security/v3/x/ccv/provider/types"
)

func NewHandler(k *keeper.Keeper) sdk.Handler {
	msgServer := keeper.NewMsgServerImpl(k)

	return func(ctx sdk.Context, msg sdk.Msg) (*sdk.Result, error) {
		ctx = ctx.WithEventManager(sdk.NewEventManager())

		switch msg := msg.(type) {
		case *types.MsgAssignConsumerKey:
			res, err := msgServer.AssignConsumerKey(sdk.WrapSDKContext(ctx), msg)
			return sdk.WrapServiceResult(ctx, res, err)
		default:
			return nil, sdkerrors.Wrapf(sdkerrorstypes.ErrUnknownRequest, "unrecognized %s message type: %T", types.ModuleName, msg)
		}
	}
}
