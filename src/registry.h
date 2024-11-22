#pragma once
#include <iostream>
#include <mutex>
#include <set>
#include <shared_mutex>
#include <vector>

template <typename HANDLE, typename ELEMENT> class Registry
{
public:
    HANDLE add(std::unique_ptr<ELEMENT> new_element)
    {
        if (free_handles.size() > 0)
        {
            std::unique_lock write_lock(mutex);
            if (free_handles.size() > 0)
            {
                HANDLE handle = free_handles[free_handles.size() - 1];
                free_handles.pop_back();
                registry[handle] = std::move(new_element);
                return handle;
            }
        }
        std::unique_lock write_lock(mutex);
        registry.push_back(std::move(new_element));
        return registry.size() - 1;
    }

    ELEMENT * get(HANDLE handle)
    {
        std::shared_lock lock(mutex);
        if (handle >= registry.size())
        {
            return nullptr;
        }
        return registry[handle].get();
    }

    void remove(HANDLE handle)
    {
        std::unique_lock lock(mutex);
        if (handle < registry.size() && registry[handle])
        {
            registry[handle].reset();
            free_handles.push_back(handle);
        }
    }

private:
    std::vector<std::unique_ptr<ELEMENT>> registry;
    mutable std::shared_mutex mutex;
    std::vector<HANDLE> free_handles;
};
