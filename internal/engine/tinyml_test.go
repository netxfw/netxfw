package engine

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestNewTinyMLEngine tests NewTinyMLEngine function
// TestNewTinyMLEngine 测试 NewTinyMLEngine 函数
func TestNewTinyMLEngine(t *testing.T) {
	engine := NewTinyMLEngine()
	assert.NotNil(t, engine)
	assert.False(t, engine.modelLoaded)
}

// TestTinyMLEngine_LoadModel tests LoadModel function
// TestTinyMLEngine_LoadModel 测试 LoadModel 函数
func TestTinyMLEngine_LoadModel(t *testing.T) {
	engine := NewTinyMLEngine()
	ctx := context.Background()

	// Test loading model
	// 测试加载模型
	err := engine.LoadModel(ctx, "/path/to/model.tflite")
	assert.NoError(t, err)
	assert.True(t, engine.modelLoaded)
}

// TestTinyMLEngine_LoadModel_EmptyPath tests LoadModel with empty path
// TestTinyMLEngine_LoadModel_EmptyPath 测试 LoadModel 使用空路径
func TestTinyMLEngine_LoadModel_EmptyPath(t *testing.T) {
	engine := NewTinyMLEngine()
	ctx := context.Background()

	// Test loading with empty path
	// 测试使用空路径加载
	err := engine.LoadModel(ctx, "")
	assert.NoError(t, err)
	assert.True(t, engine.modelLoaded)
}

// TestTinyMLEngine_Predict tests Predict function
// TestTinyMLEngine_Predict 测试 Predict 函数
func TestTinyMLEngine_Predict(t *testing.T) {
	engine := NewTinyMLEngine()
	ctx := context.Background()

	// Test predict without model loaded
	// 测试未加载模型时的预测
	score, err := engine.Predict([]byte{1, 2, 3, 4})
	assert.NoError(t, err)
	assert.Equal(t, float32(0), score)

	// Load model and test predict
	// 加载模型并测试预测
	err = engine.LoadModel(ctx, "/path/to/model.tflite")
	assert.NoError(t, err)

	score, err = engine.Predict([]byte{1, 2, 3, 4})
	assert.NoError(t, err)
	assert.Equal(t, float32(0.1), score)
}

// TestTinyMLEngine_Predict_EmptyData tests Predict with empty data
// TestTinyMLEngine_Predict_EmptyData 测试 Predict 使用空数据
func TestTinyMLEngine_Predict_EmptyData(t *testing.T) {
	engine := NewTinyMLEngine()
	ctx := context.Background()

	// Test predict with empty data without model
	// 测试未加载模型时使用空数据预测
	score, err := engine.Predict([]byte{})
	assert.NoError(t, err)
	assert.Equal(t, float32(0), score)

	// Load model and test with empty data
	// 加载模型并测试空数据
	err = engine.LoadModel(ctx, "/path/to/model.tflite")
	assert.NoError(t, err)

	score, err = engine.Predict([]byte{})
	assert.NoError(t, err)
	assert.Equal(t, float32(0.1), score)
}

// TestTinyMLEngine_Predict_NilData tests Predict with nil data
// TestTinyMLEngine_Predict_NilData 测试 Predict 使用 nil 数据
func TestTinyMLEngine_Predict_NilData(t *testing.T) {
	engine := NewTinyMLEngine()
	ctx := context.Background()

	// Test predict with nil data without model
	// 测试未加载模型时使用 nil 数据预测
	score, err := engine.Predict(nil)
	assert.NoError(t, err)
	assert.Equal(t, float32(0), score)

	// Load model and test with nil data
	// 加载模型并测试 nil 数据
	err = engine.LoadModel(ctx, "/path/to/model.tflite")
	assert.NoError(t, err)

	score, err = engine.Predict(nil)
	assert.NoError(t, err)
	assert.Equal(t, float32(0.1), score)
}

// TestTinyMLEngine_MultipleOperations tests multiple operations in sequence
// TestTinyMLEngine_MultipleOperations 测试连续多次操作
func TestTinyMLEngine_MultipleOperations(t *testing.T) {
	engine := NewTinyMLEngine()
	ctx := context.Background()

	// Multiple predictions without model
	// 未加载模型时的多次预测
	for i := 0; i < 5; i++ {
		score, err := engine.Predict([]byte{byte(i)})
		assert.NoError(t, err)
		assert.Equal(t, float32(0), score)
	}

	// Load model
	// 加载模型
	err := engine.LoadModel(ctx, "/path/to/model.tflite")
	assert.NoError(t, err)

	// Multiple predictions with model
	// 加载模型后的多次预测
	for i := 0; i < 5; i++ {
		score, err := engine.Predict([]byte{byte(i)})
		assert.NoError(t, err)
		assert.Equal(t, float32(0.1), score)
	}
}

// TestTinyMLEngine_ReloadModel tests reloading model
// TestTinyMLEngine_ReloadModel 测试重新加载模型
func TestTinyMLEngine_ReloadModel(t *testing.T) {
	engine := NewTinyMLEngine()
	ctx := context.Background()

	// Load model first time
	// 第一次加载模型
	err := engine.LoadModel(ctx, "/path/to/model1.tflite")
	assert.NoError(t, err)
	assert.True(t, engine.modelLoaded)

	// Load model second time (should still work)
	// 第二次加载模型（应该仍然工作）
	err = engine.LoadModel(ctx, "/path/to/model2.tflite")
	assert.NoError(t, err)
	assert.True(t, engine.modelLoaded)
}
