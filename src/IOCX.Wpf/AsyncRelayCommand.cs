using System.Windows.Input;

namespace IOCX.Wpf;

/// <summary>An <see cref="ICommand"/> for asynchronous handlers.</summary>
/// <remarks>
/// <see cref="RelayCommand"/> takes a synchronous delegate, so binding an async method to it
/// discards the returned task. Exceptions are lost and the command re-enables before the work
/// finishes. This type awaits the handler, blocks re-entry while it is running, and surfaces
/// faults through <c>onError</c> instead of letting them escape onto the dispatcher.
/// </remarks>
public sealed class AsyncRelayCommand : ICommand
{
    private readonly Func<object?, Task> _execute;
    private readonly Predicate<object?>? _canExecute;
    private readonly Action<Exception>? _onError;

    private bool _isRunning;

    public AsyncRelayCommand(
        Func<object?, Task> execute,
        Predicate<object?>? canExecute = null,
        Action<Exception>? onError = null)
    {
        _execute = execute ?? throw new ArgumentNullException(nameof(execute));
        _canExecute = canExecute;
        _onError = onError;
    }

    /// <inheritdoc />
    public bool CanExecute(object? parameter) =>
        !_isRunning && (_canExecute?.Invoke(parameter) ?? true);

    /// <inheritdoc />
    public async void Execute(object? parameter)
    {
        if (!CanExecute(parameter))
        {
            return;
        }

        _isRunning = true;
        CommandManager.InvalidateRequerySuggested();

        try
        {
            await _execute(parameter);
        }
        catch (OperationCanceledException)
        {
            // Cancellation is a normal outcome, not a fault.
        }
        catch (Exception ex) when (_onError is not null)
        {
            _onError(ex);
        }
        finally
        {
            _isRunning = false;
            CommandManager.InvalidateRequerySuggested();
        }
    }

    /// <inheritdoc />
    public event EventHandler? CanExecuteChanged
    {
        add => CommandManager.RequerySuggested += value;
        remove => CommandManager.RequerySuggested -= value;
    }
}
