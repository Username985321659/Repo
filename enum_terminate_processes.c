#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <psapi.h>

#define MENU "1 - Enumerate Processes\n2 - Terminate Process\n3 - Exit\n>> "

void print_process_list()
{
    DWORD processes[1024], cbNeeded, processCount;

    if (!EnumProcesses(processes, sizeof(processes), &cbNeeded))
    {
        printf("Unable to enumerate processes.\n");
        return;
    }

    processCount = cbNeeded / sizeof(DWORD);
    printf("List of all processes:\n");

    for (unsigned int i = 0; i < processCount; i++)
    {
        DWORD pid = processes[i];
        if (pid != 0)
        {
            // Get process name
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
            if (hProcess)
            {
                TCHAR processName[MAX_PATH] = TEXT("<unknown>");
                if (GetModuleBaseName(hProcess, NULL, processName, sizeof(processName) / sizeof(TCHAR)))
                {
                    printf("PID: %u, Process Name: %s\n", pid, processName);
                }
                CloseHandle(hProcess);
            }
        }
    }
}

int terminate_process(DWORD pid)
{
    HANDLE hProcess = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (hProcess == NULL)
    {
        printf("Error: Unable to open process with PID %lu\n", pid);
        return -1;
    }

    if (TerminateProcess(hProcess, 0))
    {
        printf("Successfully terminated process with PID %lu\n", pid);
    }
    else
    {
        printf("Error: Unable to terminate process with PID %lu\n", pid);
    }

    CloseHandle(hProcess);
    return 0;
}

void Terminate()
{
    DWORD pid_to_terminate;
    printf("\nEnter the PID to terminate: ");
    scanf("%lu", &pid_to_terminate);

    if (terminate_process(pid_to_terminate) == -1)
    {
        printf("Failed to terminate process.\n");
    }
}

int main()
{
    while(1)
    {
        int choice = 0;
        printf(MENU);
        scanf("%d", &choice);

        switch (choice){
            case 1:
                print_process_list();
                continue;
            case 2:
                Terminate();
                continue;
            case 3:
                break;
            default:
                printf("invalid input\n");
        }

    }
    return 0;
}
