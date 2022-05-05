// Code generated by mockery v2.9.4. DO NOT EDIT.

package mocks

import (
	context "context"

	api "github.com/jaredpetersen/vaultx/api"

	mock "github.com/stretchr/testify/mock"
)

// API is an autogenerated mock type for the API type
type API struct {
	mock.Mock
}

// Read provides a mock function with given fields: ctx, path, vaultToken
func (_m *API) Read(ctx context.Context, path string, vaultToken string) (*api.Response, error) {
	ret := _m.Called(ctx, path, vaultToken)

	var r0 *api.Response
	if rf, ok := ret.Get(0).(func(context.Context, string, string) *api.Response); ok {
		r0 = rf(ctx, path, vaultToken)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*api.Response)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string) error); ok {
		r1 = rf(ctx, path, vaultToken)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}

// Write provides a mock function with given fields: ctx, path, vaultToken, payload
func (_m *API) Write(ctx context.Context, path string, vaultToken string, payload interface{}) (*api.Response, error) {
	ret := _m.Called(ctx, path, vaultToken, payload)

	var r0 *api.Response
	if rf, ok := ret.Get(0).(func(context.Context, string, string, interface{}) *api.Response); ok {
		r0 = rf(ctx, path, vaultToken, payload)
	} else {
		if ret.Get(0) != nil {
			r0 = ret.Get(0).(*api.Response)
		}
	}

	var r1 error
	if rf, ok := ret.Get(1).(func(context.Context, string, string, interface{}) error); ok {
		r1 = rf(ctx, path, vaultToken, payload)
	} else {
		r1 = ret.Error(1)
	}

	return r0, r1
}