import service from '../utils/request'

export const login = (data) => {
  return service({
    url: '',
    method: 'get',
    params: {
      ...data,
    },
  })
}
