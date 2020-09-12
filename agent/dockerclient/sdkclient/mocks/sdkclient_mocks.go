// Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
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
// Source: github.com/aws/amazon-ecs-agent/agent/dockerclient/sdkclient (interfaces: Client)

// Package mock_sdkclient is a generated GoMock package.
package mock_sdkclient

import (
	context "context"
	io "io"
	reflect "reflect"
	time "time"

	types "github.com/docker/docker/api/types"
	container "github.com/docker/docker/api/types/container"
	events "github.com/docker/docker/api/types/events"
	filters "github.com/docker/docker/api/types/filters"
	network "github.com/docker/docker/api/types/network"
	volume "github.com/docker/docker/api/types/volume"
	gomock "github.com/golang/mock/gomock"
)

// MockClient is a mock of Client interface
type MockClient struct {
	ctrl     *gomock.Controller
	recorder *MockClientMockRecorder
}

// MockClientMockRecorder is the mock recorder for MockClient
type MockClientMockRecorder struct {
	mock *MockClient
}

// NewMockClient creates a new mock instance
func NewMockClient(ctrl *gomock.Controller) *MockClient {
	mock := &MockClient{ctrl: ctrl}
	mock.recorder = &MockClientMockRecorder{mock}
	return mock
}

// EXPECT returns an object that allows the caller to indicate expected use
func (m *MockClient) EXPECT() *MockClientMockRecorder {
	return m.recorder
}

// ClientVersion mocks base method
func (m *MockClient) ClientVersion() string {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ClientVersion")
	ret0, _ := ret[0].(string)
	return ret0
}

// ClientVersion indicates an expected call of ClientVersion
func (mr *MockClientMockRecorder) ClientVersion() *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ClientVersion", reflect.TypeOf((*MockClient)(nil).ClientVersion))
}

// ContainerCreate mocks base method
func (m *MockClient) ContainerCreate(arg0 context.Context, arg1 *container.Config, arg2 *container.HostConfig, arg3 *network.NetworkingConfig, arg4 string) (container.ContainerCreateCreatedBody, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContainerCreate", arg0, arg1, arg2, arg3, arg4)
	ret0, _ := ret[0].(container.ContainerCreateCreatedBody)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ContainerCreate indicates an expected call of ContainerCreate
func (mr *MockClientMockRecorder) ContainerCreate(arg0, arg1, arg2, arg3, arg4 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContainerCreate", reflect.TypeOf((*MockClient)(nil).ContainerCreate), arg0, arg1, arg2, arg3, arg4)
}

// ContainerExecStart mocks base method
func (m *MockClient) ContainerExecStart(arg0 context.Context, arg1 string, arg2 types.ExecStartCheck) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContainerExecStart", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// ContainerExecStart indicates an expected call of ContainerExecStart
func (mr *MockClientMockRecorder) ContainerExecStart(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContainerExecStart", reflect.TypeOf((*MockClient)(nil).ContainerExecStart), arg0, arg1, arg2)
}

// ContainerInspect mocks base method
func (m *MockClient) ContainerInspect(arg0 context.Context, arg1 string) (types.ContainerJSON, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContainerInspect", arg0, arg1)
	ret0, _ := ret[0].(types.ContainerJSON)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ContainerInspect indicates an expected call of ContainerInspect
func (mr *MockClientMockRecorder) ContainerInspect(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContainerInspect", reflect.TypeOf((*MockClient)(nil).ContainerInspect), arg0, arg1)
}

// ContainerList mocks base method
func (m *MockClient) ContainerList(arg0 context.Context, arg1 types.ContainerListOptions) ([]types.Container, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContainerList", arg0, arg1)
	ret0, _ := ret[0].([]types.Container)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ContainerList indicates an expected call of ContainerList
func (mr *MockClientMockRecorder) ContainerList(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContainerList", reflect.TypeOf((*MockClient)(nil).ContainerList), arg0, arg1)
}

// ContainerRemove mocks base method
func (m *MockClient) ContainerRemove(arg0 context.Context, arg1 string, arg2 types.ContainerRemoveOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContainerRemove", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// ContainerRemove indicates an expected call of ContainerRemove
func (mr *MockClientMockRecorder) ContainerRemove(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContainerRemove", reflect.TypeOf((*MockClient)(nil).ContainerRemove), arg0, arg1, arg2)
}

// ContainerStart mocks base method
func (m *MockClient) ContainerStart(arg0 context.Context, arg1 string, arg2 types.ContainerStartOptions) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContainerStart", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// ContainerStart indicates an expected call of ContainerStart
func (mr *MockClientMockRecorder) ContainerStart(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContainerStart", reflect.TypeOf((*MockClient)(nil).ContainerStart), arg0, arg1, arg2)
}

// ContainerStats mocks base method
func (m *MockClient) ContainerStats(arg0 context.Context, arg1 string, arg2 bool) (types.ContainerStats, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContainerStats", arg0, arg1, arg2)
	ret0, _ := ret[0].(types.ContainerStats)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ContainerStats indicates an expected call of ContainerStats
func (mr *MockClientMockRecorder) ContainerStats(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContainerStats", reflect.TypeOf((*MockClient)(nil).ContainerStats), arg0, arg1, arg2)
}

// ContainerStop mocks base method
func (m *MockClient) ContainerStop(arg0 context.Context, arg1 string, arg2 *time.Duration) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContainerStop", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// ContainerStop indicates an expected call of ContainerStop
func (mr *MockClientMockRecorder) ContainerStop(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContainerStop", reflect.TypeOf((*MockClient)(nil).ContainerStop), arg0, arg1, arg2)
}

// ContainerTop mocks base method
func (m *MockClient) ContainerTop(arg0 context.Context, arg1 string, arg2 []string) (container.ContainerTopOKBody, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ContainerTop", arg0, arg1, arg2)
	ret0, _ := ret[0].(container.ContainerTopOKBody)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ContainerTop indicates an expected call of ContainerTop
func (mr *MockClientMockRecorder) ContainerTop(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ContainerTop", reflect.TypeOf((*MockClient)(nil).ContainerTop), arg0, arg1, arg2)
}

// Events mocks base method
func (m *MockClient) Events(arg0 context.Context, arg1 types.EventsOptions) (<-chan events.Message, <-chan error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Events", arg0, arg1)
	ret0, _ := ret[0].(<-chan events.Message)
	ret1, _ := ret[1].(<-chan error)
	return ret0, ret1
}

// Events indicates an expected call of Events
func (mr *MockClientMockRecorder) Events(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Events", reflect.TypeOf((*MockClient)(nil).Events), arg0, arg1)
}

// ImageImport mocks base method
func (m *MockClient) ImageImport(arg0 context.Context, arg1 types.ImageImportSource, arg2 string, arg3 types.ImageImportOptions) (io.ReadCloser, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ImageImport", arg0, arg1, arg2, arg3)
	ret0, _ := ret[0].(io.ReadCloser)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ImageImport indicates an expected call of ImageImport
func (mr *MockClientMockRecorder) ImageImport(arg0, arg1, arg2, arg3 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ImageImport", reflect.TypeOf((*MockClient)(nil).ImageImport), arg0, arg1, arg2, arg3)
}

// ImageInspectWithRaw mocks base method
func (m *MockClient) ImageInspectWithRaw(arg0 context.Context, arg1 string) (types.ImageInspect, []byte, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ImageInspectWithRaw", arg0, arg1)
	ret0, _ := ret[0].(types.ImageInspect)
	ret1, _ := ret[1].([]byte)
	ret2, _ := ret[2].(error)
	return ret0, ret1, ret2
}

// ImageInspectWithRaw indicates an expected call of ImageInspectWithRaw
func (mr *MockClientMockRecorder) ImageInspectWithRaw(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ImageInspectWithRaw", reflect.TypeOf((*MockClient)(nil).ImageInspectWithRaw), arg0, arg1)
}

// ImageList mocks base method
func (m *MockClient) ImageList(arg0 context.Context, arg1 types.ImageListOptions) ([]types.ImageSummary, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ImageList", arg0, arg1)
	ret0, _ := ret[0].([]types.ImageSummary)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ImageList indicates an expected call of ImageList
func (mr *MockClientMockRecorder) ImageList(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ImageList", reflect.TypeOf((*MockClient)(nil).ImageList), arg0, arg1)
}

// ImageLoad mocks base method
func (m *MockClient) ImageLoad(arg0 context.Context, arg1 io.Reader, arg2 bool) (types.ImageLoadResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ImageLoad", arg0, arg1, arg2)
	ret0, _ := ret[0].(types.ImageLoadResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ImageLoad indicates an expected call of ImageLoad
func (mr *MockClientMockRecorder) ImageLoad(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ImageLoad", reflect.TypeOf((*MockClient)(nil).ImageLoad), arg0, arg1, arg2)
}

// ImagePull mocks base method
func (m *MockClient) ImagePull(arg0 context.Context, arg1 string, arg2 types.ImagePullOptions) (io.ReadCloser, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ImagePull", arg0, arg1, arg2)
	ret0, _ := ret[0].(io.ReadCloser)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ImagePull indicates an expected call of ImagePull
func (mr *MockClientMockRecorder) ImagePull(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ImagePull", reflect.TypeOf((*MockClient)(nil).ImagePull), arg0, arg1, arg2)
}

// ImageRemove mocks base method
func (m *MockClient) ImageRemove(arg0 context.Context, arg1 string, arg2 types.ImageRemoveOptions) ([]types.ImageDeleteResponseItem, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ImageRemove", arg0, arg1, arg2)
	ret0, _ := ret[0].([]types.ImageDeleteResponseItem)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ImageRemove indicates an expected call of ImageRemove
func (mr *MockClientMockRecorder) ImageRemove(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ImageRemove", reflect.TypeOf((*MockClient)(nil).ImageRemove), arg0, arg1, arg2)
}

// Info mocks base method
func (m *MockClient) Info(arg0 context.Context) (types.Info, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Info", arg0)
	ret0, _ := ret[0].(types.Info)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Info indicates an expected call of Info
func (mr *MockClientMockRecorder) Info(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Info", reflect.TypeOf((*MockClient)(nil).Info), arg0)
}

// Ping mocks base method
func (m *MockClient) Ping(arg0 context.Context) (types.Ping, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "Ping", arg0)
	ret0, _ := ret[0].(types.Ping)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// Ping indicates an expected call of Ping
func (mr *MockClientMockRecorder) Ping(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "Ping", reflect.TypeOf((*MockClient)(nil).Ping), arg0)
}

// PluginList mocks base method
func (m *MockClient) PluginList(arg0 context.Context, arg1 filters.Args) (types.PluginsListResponse, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "PluginList", arg0, arg1)
	ret0, _ := ret[0].(types.PluginsListResponse)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// PluginList indicates an expected call of PluginList
func (mr *MockClientMockRecorder) PluginList(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "PluginList", reflect.TypeOf((*MockClient)(nil).PluginList), arg0, arg1)
}

// ServerVersion mocks base method
func (m *MockClient) ServerVersion(arg0 context.Context) (types.Version, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "ServerVersion", arg0)
	ret0, _ := ret[0].(types.Version)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// ServerVersion indicates an expected call of ServerVersion
func (mr *MockClientMockRecorder) ServerVersion(arg0 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "ServerVersion", reflect.TypeOf((*MockClient)(nil).ServerVersion), arg0)
}

// VolumeCreate mocks base method
func (m *MockClient) VolumeCreate(arg0 context.Context, arg1 volume.VolumeCreateBody) (types.Volume, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VolumeCreate", arg0, arg1)
	ret0, _ := ret[0].(types.Volume)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VolumeCreate indicates an expected call of VolumeCreate
func (mr *MockClientMockRecorder) VolumeCreate(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VolumeCreate", reflect.TypeOf((*MockClient)(nil).VolumeCreate), arg0, arg1)
}

// VolumeInspect mocks base method
func (m *MockClient) VolumeInspect(arg0 context.Context, arg1 string) (types.Volume, error) {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VolumeInspect", arg0, arg1)
	ret0, _ := ret[0].(types.Volume)
	ret1, _ := ret[1].(error)
	return ret0, ret1
}

// VolumeInspect indicates an expected call of VolumeInspect
func (mr *MockClientMockRecorder) VolumeInspect(arg0, arg1 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VolumeInspect", reflect.TypeOf((*MockClient)(nil).VolumeInspect), arg0, arg1)
}

// VolumeRemove mocks base method
func (m *MockClient) VolumeRemove(arg0 context.Context, arg1 string, arg2 bool) error {
	m.ctrl.T.Helper()
	ret := m.ctrl.Call(m, "VolumeRemove", arg0, arg1, arg2)
	ret0, _ := ret[0].(error)
	return ret0
}

// VolumeRemove indicates an expected call of VolumeRemove
func (mr *MockClientMockRecorder) VolumeRemove(arg0, arg1, arg2 interface{}) *gomock.Call {
	mr.mock.ctrl.T.Helper()
	return mr.mock.ctrl.RecordCallWithMethodType(mr.mock, "VolumeRemove", reflect.TypeOf((*MockClient)(nil).VolumeRemove), arg0, arg1, arg2)
}
