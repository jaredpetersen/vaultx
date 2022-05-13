// Code generated by mockery v2.9.4. DO NOT EDIT.

package mocks

import (
	auth "github.com/jaredpetersen/vaultx/auth"
	mock "github.com/stretchr/testify/mock"
)

// TokenManager is an autogenerated mock type for the TokenManager type
type TokenManager struct {
	mock.Mock
}

// GetToken provides a mock function with given fields:
func (_m *TokenManager) GetToken() auth.Token {
	ret := _m.Called()

	var r0 auth.Token
	if rf, ok := ret.Get(0).(func() auth.Token); ok {
		r0 = rf()
	} else {
		r0 = ret.Get(0).(auth.Token)
	}

	return r0
}

// SetToken provides a mock function with given fields: token
func (_m *TokenManager) SetToken(token auth.Token) {
	_m.Called(token)
}
