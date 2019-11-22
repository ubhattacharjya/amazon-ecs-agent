// Copyright 2015-2019 Amazon.com, Inc. or its affiliates. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License"). You may
// not use this file except in compliance with the License. A copy of the
// License is located at
//
//     http://aws.amazon.com/apache2.0/
//
// or in the "license" file accompanying this file. This file is distributed
// on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either
// express or implied. See the License for the specific language governing
// permissions and limitations under the License.
//

// Code generated by MockGen. DO NOT EDIT.
// Source: github.com/aws/amazon-ecs-agent/agent/s3/factory (interfaces: S3ClientCreator)

// Package mock_factory is a generated GoMock package.
package mock_factory

import (
	reflect "reflect"

	credentials "github.com/aws/amazon-ecs-agent/agent/credentials"
	s3 "github.com/aws/amazon-ecs-agent/agent/s3"
	gomock "github.com/golang/mock/gomock"
)

// MockS3ClientCreator is a mock of S3ClientCreator interface
type MockS3ClientCreator struct {
	ctrl     *gomock.Controller
	recorder *MockS3ClientCreatorMockRecorder
}

// MockS3ClientCreatorMockRecorder is the mock recorder for MockS3ClientCreator
type MockS3ClientCreatorMockRecorder struct {
	mock *MockS3ClientCreator
}

// NewMockS3ClientCreator creates a new mock instance
func NewMockS3ClientCreator(ctrl *gomock.Controller) *MockS3ClientCreator {
	mock := &MockS3ClientCreator{ctrl: ctrl}
	mock.recorder = &MockS3ClientCreatorMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockS3ClientCreator) EXPECT() *MockS3ClientCreatorMockRecorder {
	return m.recorder
}

// NewS3ClientForBucket mocks base method
func (m *MockS3ClientCreator) NewS3ClientForBucket(arg0, arg1 string, arg2 credentials.IAMRoleCredentials) (s3.S3Client, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "NewS3ClientForBucket", arg0, arg1, arg2)
	ret0, _ := ret[0].(s3.S3Client)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// NewS3ClientForBucket indicates an expected call of NewS3ClientForBucket
func (mr *MockS3ClientCreatorMockRecorder) NewS3ClientForBucket(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "NewS3ClientForBucket", reflect.TypeOf((*MockS3ClientCreator)(nil).NewS3ClientForBucket), arg0, arg1, arg2)
}
