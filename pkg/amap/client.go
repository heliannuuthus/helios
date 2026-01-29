package amap

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/heliannuuthus/helios/pkg/json"
)

// Client 高德地图客户端
type Client struct {
	apiKey       string
	weatherCache map[string]*cachedWeather
	mu           sync.RWMutex
}

type cachedWeather struct {
	data      *Weather
	expiresAt time.Time
}

// Location 位置信息
type Location struct {
	Province string
	City     string
	District string
	Adcode   string
}

// Weather 天气信息
type Weather struct {
	Temperature float64
	Humidity    int
	Weather     string
}

// NewClient 创建高德地图客户端
func NewClient(apiKey string) *Client {
	return &Client{
		apiKey:       apiKey,
		weatherCache: make(map[string]*cachedWeather),
	}
}

// GetLocation 逆地理编码
func (c *Client) GetLocation(lat, lng float64) (*Location, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("未配置 amap.api-key")
	}

	reqURL := fmt.Sprintf("https://restapi.amap.com/v3/geocode/regeo?location=%.6f,%.6f&key=%s", lng, lat, c.apiKey)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("请求高德 API 失败: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Status    string `json:"status"`
		Info      string `json:"info"`
		Infocode  string `json:"infocode"`
		Regeocode struct {
			AddressComponent struct {
				Province string `json:"province"`
				City     any    `json:"city"`
				District string `json:"district"`
				Adcode   string `json:"adcode"`
			} `json:"addressComponent"`
		} `json:"regeocode"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("解析高德响应失败: %w", err)
	}

	if result.Status != "1" {
		return nil, fmt.Errorf("高德 API 错误: %s (code: %s)", result.Info, result.Infocode)
	}

	addr := result.Regeocode.AddressComponent
	city := ""
	if v, ok := addr.City.(string); ok {
		city = v
	}
	if city == "" {
		city = addr.Province
	}

	return &Location{
		Province: addr.Province,
		City:     city,
		District: addr.District,
		Adcode:   addr.Adcode,
	}, nil
}

// GetWeatherByAdcode 根据 adcode 获取天气
func (c *Client) GetWeatherByAdcode(adcode string) (*Weather, error) {
	if c.apiKey == "" {
		return nil, fmt.Errorf("未配置 amap.api-key")
	}

	reqURL := fmt.Sprintf("https://restapi.amap.com/v3/weather/weatherInfo?city=%s&key=%s&extensions=base", adcode, c.apiKey)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, reqURL, nil)
	if err != nil {
		return nil, fmt.Errorf("创建请求失败: %w", err)
	}

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() { _ = resp.Body.Close() }()

	var result struct {
		Status string `json:"status"`
		Lives  []struct {
			Temperature string `json:"temperature"`
			Humidity    string `json:"humidity"`
			Weather     string `json:"weather"`
		} `json:"lives"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, err
	}

	if result.Status != "1" || len(result.Lives) == 0 {
		return nil, fmt.Errorf("获取天气失败")
	}

	live := result.Lives[0]
	var temp float64
	var humidity int
	if _, err := fmt.Sscanf(live.Temperature, "%f", &temp); err != nil {
		temp = 20 // 默认温度
	}
	if _, err := fmt.Sscanf(live.Humidity, "%d", &humidity); err != nil {
		humidity = 50 // 默认湿度
	}

	return &Weather{
		Temperature: temp,
		Humidity:    humidity,
		Weather:     live.Weather,
	}, nil
}

// GetWeather 根据经纬度获取天气（带缓存）
func (c *Client) GetWeather(lat, lng float64) (*Weather, error) {
	cacheKey := fmt.Sprintf("%.1f,%.1f", lat, lng)

	c.mu.RLock()
	if cached, ok := c.weatherCache[cacheKey]; ok && time.Now().Before(cached.expiresAt) {
		c.mu.RUnlock()
		return cached.data, nil
	}
	c.mu.RUnlock()

	location, err := c.GetLocation(lat, lng)
	if err != nil {
		return nil, err
	}

	weather, err := c.GetWeatherByAdcode(location.Adcode)
	if err != nil {
		return nil, err
	}

	c.mu.Lock()
	c.weatherCache[cacheKey] = &cachedWeather{
		data:      weather,
		expiresAt: time.Now().Add(30 * time.Minute),
	}
	c.mu.Unlock()

	return weather, nil
}
