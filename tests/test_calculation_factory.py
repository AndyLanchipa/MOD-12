import pytest

from app.services.calculation_factory import CalculationFactory


class TestCalculationFactory:
    """Test cases for the CalculationFactory class"""

    def test_add_operation(self):
        """Test addition operation through factory"""
        result = CalculationFactory.calculate(5, 3, "Add")
        assert result == 8

    def test_subtract_operation(self):
        """Test subtraction operation through factory"""
        result = CalculationFactory.calculate(5, 3, "Sub")
        assert result == 2

    def test_multiply_operation(self):
        """Test multiplication operation through factory"""
        result = CalculationFactory.calculate(5, 3, "Multiply")
        assert result == 15

    def test_divide_operation(self):
        """Test division operation through factory"""
        result = CalculationFactory.calculate(6, 3, "Divide")
        assert result == 2

    def test_divide_by_zero_raises_error(self):
        """Test that division by zero raises appropriate error"""
        with pytest.raises(ValueError, match="Division by zero is not allowed"):
            CalculationFactory.calculate(5, 0, "Divide")

    def test_invalid_operation_type(self):
        """Test that invalid operation type raises error"""
        with pytest.raises(ValueError, match="Unsupported operation type"):
            CalculationFactory.calculate(5, 3, "InvalidOperation")

    def test_get_operation_success(self):
        """Test successful operation retrieval"""
        operation = CalculationFactory.get_operation("Add")
        assert operation is not None
        assert hasattr(operation, "calculate")

    def test_get_operation_failure(self):
        """Test operation retrieval with invalid type"""
        with pytest.raises(ValueError):
            CalculationFactory.get_operation("InvalidType")

    def test_get_supported_operations(self):
        """Test getting list of supported operations"""
        operations = CalculationFactory.get_supported_operations()
        expected_operations = ["Add", "Sub", "Multiply", "Divide"]
        assert set(operations) == set(expected_operations)

    def test_is_operation_supported(self):
        """Test operation support checking"""
        assert CalculationFactory.is_operation_supported("Add") is True
        assert CalculationFactory.is_operation_supported("InvalidType") is False

    def test_floating_point_operations(self):
        """Test operations with floating point numbers"""
        result = CalculationFactory.calculate(5.5, 2.5, "Add")
        assert result == 8.0

        result = CalculationFactory.calculate(10.0, 3.0, "Divide")
        assert abs(result - 3.3333333333333335) < 1e-10

    def test_negative_numbers(self):
        """Test operations with negative numbers"""
        result = CalculationFactory.calculate(-5, 3, "Add")
        assert result == -2

        result = CalculationFactory.calculate(-10, -2, "Divide")
        assert result == 5
