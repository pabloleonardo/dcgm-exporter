/*
 * Copyright (c) 2024, NVIDIA CORPORATION.  All rights reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package transformation

import (
	"bufio"
	"context"
	"fmt"
	stdos "os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/docker/docker/api/types/container"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"

	"github.com/NVIDIA/dcgm-exporter/internal/pkg/appconfig"
	"github.com/NVIDIA/dcgm-exporter/internal/pkg/collector"
	"github.com/NVIDIA/dcgm-exporter/internal/pkg/deviceinfo"
)

type DockerMapper struct {
	Config        *appconfig.Config
	client        *client.Client
	containerInfo map[string]ContainerInfo
}

type ContainerInfo struct {
	Name   string
	ID     string
	Labels map[string]string
}

const (
	cgroupV1NvidiaPath = "/sys/fs/cgroup/devices/docker"
	cgroupV2NvidiaPath = "/sys/fs/cgroup"
	procCgroupPath     = "/proc/self/cgroup"
	dockerAPITimeout   = 5 * time.Second
)

var (
	dockerContainerIDRegex = regexp.MustCompile(`docker/([a-f0-9]{64})`)
	cgroupV2ContainerRegex = regexp.MustCompile(`docker-([a-f0-9]{64})\.scope`)
)

func NewDockerMapper(c *appconfig.Config) *DockerMapper {
	return &DockerMapper{
		Config:        c,
		containerInfo: make(map[string]ContainerInfo),
	}
}

func (d *DockerMapper) Name() string {
	return "DockerMapper"
}

func (d *DockerMapper) Process(metrics collector.MetricsByCounter, deviceInfo deviceinfo.Provider) error {
	if err := d.initDockerClient(); err != nil {
		logrus.Warnf("Failed to initialize Docker client, falling back to cgroup parsing: %v", err)
		return d.processUsingCgroups(metrics, deviceInfo)
	}

	defer d.closeDockerClient()

	if err := d.loadContainerInfo(); err != nil {
		logrus.Warnf("Failed to load container info from Docker API, falling back to cgroup parsing: %v", err)
		return d.processUsingCgroups(metrics, deviceInfo)
	}

	return d.processUsingDockerAPI(metrics, deviceInfo)
}

func (d *DockerMapper) initDockerClient() error {
	var err error
	d.client, err = client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return fmt.Errorf("failed to create Docker client: %w", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), dockerAPITimeout)
	defer cancel()

	_, err = d.client.Ping(ctx)
	if err != nil {
		return fmt.Errorf("failed to ping Docker daemon: %w", err)
	}

	return nil
}

func (d *DockerMapper) closeDockerClient() {
	if d.client != nil {
		d.client.Close()
	}
}

func (d *DockerMapper) loadContainerInfo() error {
	ctx, cancel := context.WithTimeout(context.Background(), dockerAPITimeout)
	defer cancel()

	containers, err := d.client.ContainerList(ctx, container.ListOptions{})
	if err != nil {
		return fmt.Errorf("failed to list containers: %w", err)
	}

	d.containerInfo = make(map[string]ContainerInfo)
	for _, container := range containers {
		info := ContainerInfo{
			ID:     container.ID,
			Labels: container.Labels,
		}

		if len(container.Names) > 0 {
			info.Name = strings.TrimPrefix(container.Names[0], "/")
		} else {
			info.Name = container.ID[:12]
		}

		d.containerInfo[container.ID] = info
		d.containerInfo[container.ID[:12]] = info
	}

	logrus.Debugf("Loaded %d containers from Docker API", len(containers))
	return nil
}

func (d *DockerMapper) processUsingDockerAPI(metrics collector.MetricsByCounter, deviceInfo deviceinfo.Provider) error {
	containerID, err := d.getCurrentContainerID()
	if err != nil {
		return fmt.Errorf("failed to get current container ID: %w", err)
	}

	containerInfo, exists := d.containerInfo[containerID]
	if !exists {
		logrus.Warnf("Container %s not found in loaded container info", containerID)
		return nil
	}

	return d.addContainerLabelsToMetrics(metrics, containerInfo)
}

func (d *DockerMapper) processUsingCgroups(metrics collector.MetricsByCounter, deviceInfo deviceinfo.Provider) error {
	containerID, err := d.getCurrentContainerID()
	if err != nil {
		return fmt.Errorf("failed to get current container ID from cgroups: %w", err)
	}

	containerInfo := ContainerInfo{
		ID:     containerID,
		Name:   containerID[:12],
		Labels: make(map[string]string),
	}

	return d.addContainerLabelsToMetrics(metrics, containerInfo)
}

func (d *DockerMapper) getCurrentContainerID() (string, error) {
	file, err := stdos.Open(procCgroupPath)
	if err != nil {
		return "", fmt.Errorf("failed to open %s: %w", procCgroupPath, err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := scanner.Text()
		
		if matches := dockerContainerIDRegex.FindStringSubmatch(line); len(matches) > 1 {
			return matches[1], nil
		}
		
		if matches := cgroupV2ContainerRegex.FindStringSubmatch(line); len(matches) > 1 {
			return matches[1], nil
		}
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading %s: %w", procCgroupPath, err)
	}

	return "", fmt.Errorf("could not find Docker container ID in cgroups")
}

func (d *DockerMapper) addContainerLabelsToMetrics(metrics collector.MetricsByCounter, containerInfo ContainerInfo) error {
	for counter, metricList := range metrics {
		for i := range metricList {
			if metricList[i].Attributes == nil {
				metricList[i].Attributes = make(map[string]string)
			}

			if !d.Config.UseOldNamespace {
				metricList[i].Attributes[containerAttribute] = containerInfo.Name
			} else {
				metricList[i].Attributes[oldContainerAttribute] = containerInfo.Name
			}

			metricList[i].Attributes["container_id"] = containerInfo.ID

			for labelKey, labelValue := range containerInfo.Labels {
				if d.Config.DockerEnableContainerLabels {
					sanitizedKey := d.sanitizeLabelKey(labelKey)
					metricList[i].Attributes[sanitizedKey] = labelValue
				}
			}
		}
		
		logrus.Debugf("Added container info to %d metrics for counter %s: container=%s, id=%s", 
			len(metricList), counter, containerInfo.Name, containerInfo.ID[:12])
	}

	return nil
}

func (d *DockerMapper) sanitizeLabelKey(key string) string {
	sanitized := strings.ReplaceAll(key, ".", "_")
	sanitized = strings.ReplaceAll(sanitized, "-", "_")
	sanitized = strings.ReplaceAll(sanitized, "/", "_")
	return sanitized
}

func (d *DockerMapper) getGPUDevicesFromCgroups() ([]string, error) {
	var gpuDevices []string

	cgroupPaths := []string{cgroupV1NvidiaPath, cgroupV2NvidiaPath}
	
	for _, basePath := range cgroupPaths {
		devices, err := d.scanForGPUDevices(basePath)
		if err != nil {
			logrus.Debugf("Failed to scan %s for GPU devices: %v", basePath, err)
			continue
		}
		gpuDevices = append(gpuDevices, devices...)
	}

	if len(gpuDevices) == 0 {
		return nil, fmt.Errorf("no GPU devices found in cgroups")
	}

	return gpuDevices, nil
}

func (d *DockerMapper) scanForGPUDevices(basePath string) ([]string, error) {
	var devices []string

	err := filepath.Walk(basePath, func(path string, info stdos.FileInfo, err error) error {
		if err != nil {
			return nil
		}

		if strings.Contains(path, "nvidia") && info.IsDir() {
			devicesFile := filepath.Join(path, "devices.list")
			if _, err := stdos.Stat(devicesFile); err == nil {
				gpuDevs, err := d.parseDevicesList(devicesFile)
				if err == nil {
					devices = append(devices, gpuDevs...)
				}
			}
		}

		return nil
	})

	return devices, err
}

func (d *DockerMapper) parseDevicesList(devicesFile string) ([]string, error) {
	file, err := stdos.Open(devicesFile)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var devices []string
	scanner := bufio.NewScanner(file)
	
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "c ") && strings.Contains(line, "195:") {
			parts := strings.Fields(line)
			if len(parts) >= 3 {
				deviceParts := strings.Split(parts[1], ":")
				if len(deviceParts) == 2 {
					minor, err := strconv.Atoi(deviceParts[1])
					if err == nil {
						devices = append(devices, fmt.Sprintf("nvidia%d", minor))
					}
				}
			}
		}
	}

	return devices, scanner.Err()
}