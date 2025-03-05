import unittest
from unittest.mock import patch, MagicMock
from ai_module.ai_integration import call_ai_model, generate_smart_payload

class TestAIIntegration(unittest.TestCase):
    @patch('ai_module.ai_integration.requests.post')
    @patch('ai_module.ai_integration.get_api_key')
    def test_call_ai_model(self, mock_get_api_key, mock_post):
        # 设置模拟
        mock_get_api_key.return_value = "fake_api_key"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "测试响应"}}]
        }
        mock_post.return_value = mock_response
        
        # 调用函数
        result = call_ai_model("测试提示")
        
        # 验证结果
        self.assertEqual(result, "测试响应")
        mock_post.assert_called_once()
        
    @patch('ai_module.ai_integration.call_ai_model')
    def test_generate_smart_payload(self, mock_call_ai_model):
        # 设置模拟
        mock_call_ai_model.return_value = "测试payload"
        
        # 调用函数
        result = generate_smart_payload("mysql", "union")
        
        # 验证结果
        self.assertEqual(result, "测试payload")
        mock_call_ai_model.assert_called_once()
